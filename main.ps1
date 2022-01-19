<#
 .Synopsis
  Get Shared Credential from AWS SSO
 
 .Description
  Get Shared Credential from AWS SSO
 
 .Parameter accountFilter
  Array of string for your account filtering. Use wildcard (*) allowed. It is not suggested that you run this without filter if you have many roles.

 .Parameter defaultRole
  Which Role do you want to use as your default role. Use the expected nickname such as poc-dx_ReadOnly.

 .Parameter noLoop
  If you use this switch then this cmdlet will NOT go into a loop. Do this to get your credential just this once. 

 .Example - Get all the roles and go into a loop, no default role
  get-ssoRoles 

 .Example - Get only few roles, set example, and no loop
  get-ssoRoles -accountFilter ("poc*","dev*","prod*") -defaultRole "poc-A_ReadOnly" -noLoop
#>
function get-ssoroles{
    param(
        [Parameter(Mandatory = $false)]
        [array]
        $accountFilter = $null,

        [Parameter(Mandatory = $false)]
        [string]
        $defaultRole = "",
        
        [Parameter(Mandatory = $false)]
        [switch]
        $noLoop
    )
    ###########
    write-host "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
    write-host "Get AWS SSO Credentials"
    write-host "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
    ###########
    try{
        $version = (get-module -listavailable -name Stifel.CloudAuthenticator.PSModule | sort -Descending)[0].version
        write-host "Version: $version"
    }catch{
        write-host "Could not determine version"
    }
    ##This only changes if we have another AWS Organization
    $startUrl = "https://yourapps.awsapps.com/start#/"

    ##if noloop is toggled then we need to set this to false AFTER the script runs once
    $keepLoop = $true

    ##basic housekeeping file locations
    $credentialFile = "$env:userprofile\.aws\credentials"
    $backCredentialFile = "$env:userprofile\.aws\credentials_backup"
    $tempCredentialFile = "$env:userprofile\.aws\credentials_temp"
    $deviceRegisterFile = "$env:userprofile\.aws\deviceregister"
    $accessTokenFile = "$env:userprofile\.aws\accesstoken"

    ##Your Name goes here
    $myName = $env:UserName

    $region = aws configure get region
    if ($null -eq $region){
        write-host "Default region not found. Setting to us-east-1. You're welcome."
        aws configure set region "us-east-1"
    }

    $tzone = get-timezone

    ###################################################################
    if(test-path $deviceRegisterFile){
        $registInfoJSON = get-content -path $deviceRegisterFile
        try{
            $registInfo = $registInfoJSON | out-string | convertfrom-json
        }catch{
            write-host "Invalid JSON format for $deviceRegisterFile, please fix or delete file."
            $registInfo = $null
        }
    }else{
        write-host "Register not found. Registering."
        $registInfo = $null
    }

    $skipRegister = $false
    if($null -ne $registInfo.clientSecretExpiresAt){
        $clientSecretExpire = ((Get-Date 01.01.1970).addHours( - ($tzone.baseutcoffset.totalhours))) + ([System.TimeSpan]::fromseconds($registInfo.clientSecretExpiresAt))
        if ($clientSecretExpire -gt (get-date)){
            $skipRegister = $true
            write-host "Registeration found. Skip registeration."
        }else{
            write-host "Registeration Expired. Re-registering."
        }
    }

    if($skipRegister -eq $false){
        ##Register this device
        try{
            $registInfoJSON = aws sso-oidc register-client --client-name $myName --client-type "public" 
        }catch{
            Write-Warning "Register Client error: $($_.Exception.Message)"
        }
        #parse the content of register Info
        $registInfo = $registInfoJSON | convertfrom-json
        # create a securestring then create a text version of it
        $registInfo.clientSecret = $registInfo.clientSecret | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString

        try{
            out-file -FilePath $deviceRegisterFile -InputObject ($registInfo | convertTo-json) -Encoding utf8 -Force
        }catch{
            Write-Warning "Write to file error: $($_.Exception.Message)"
        }
        
        ##somehow this is like good for 3 months?
        $clientSecretExpire = ((Get-Date 01.01.1970).addHours( - ($tzone.baseutcoffset.totalhours))) + ([System.TimeSpan]::fromseconds($registInfo.clientSecretExpiresAt))
        write-host "Register Success"
    }

    
    #this is encrypted, let's make it into secure string so we can use it
    $clientId = $registInfo.clientId
    # need to decrypt the register info found in the file and treat it as a secure string
    $secureClientPassword = $registInfo.clientSecret | ConvertTo-SecureString
    $clientCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $clientId, $secureClientPassword 
    $clientSecret = $clientCredentials.GetNetworkCredential().Password
    write-host "Client ID: $clientId"  
    write-host "This Client will expire on $clientSecretExpire"
    
    ##########################################################################
    ##########################################################################
    ##Check if access token is expired
    ## Add to file
    if(test-path $accessTokenFile){
        $myTokenJson = get-content -path $accessTokenFile
        try{
            $myToken = $myTokenJson | out-string | convertfrom-json
        }catch{
            write-host "Invalid JSON format for $accessTokenFile, please fix or delete file."
            $myToken = $null
        }
    }else{
        write-host "AccessToken not found. Regenerating."
        $myToken = $null
    }
    
    $skipToken = $false
    if($null -ne $myToken.expiration){
        $tokenExpiresInWhen = (Get-Date 01.01.1970) + ([System.TimeSpan]::fromseconds($myToken.expiration))
        if ($tokenExpiresInWhen -gt (get-date)){
            $skipToken = $true
            write-host "AccessToken found."
        }else{
            write-host "AccessToken Expired. Regenerating."
        }
    }

    if ($noLoop -eq $false){
        write-host "Refreshing token at top of loop"
        $skipToken = $false
    }
    #If we're looping, force this
    if($skipToken -eq $false){
        ## get device authorization, basically log into AWS SSO
        try{
            $deviceAuthorizationJSON = aws sso-oidc start-device-authorization --client-id $clientId --client-secret $clientSecret --start-url $startUrl
        }catch{
            Write-Warning "Device Authorization error: $($_.Exception.Message)"
        }
        $deviceAuthorization = $deviceAuthorizationJSON | convertfrom-json

        $deviceCode = $deviceAuthorization.deviceCode
        #Unused attributes
        #$userCode = $deviceAuthorization.userCode
        #$verificationUri = $deviceAuthorization.verificationUri
        #$verificationUriComplete = $deviceAuthorization.verificationUriComplete
        #$deviceAuthExpiresInSec = $deviceAuthorization.expiresIn
    
        ##You have 10 minutes to validate yourself here
        write-host "You will now be redirected to a browser to complete your login to SSO. Do so and return here"
        write-host "You can also enter this from any browser on any machine: $verificationUriComplete"
        read-host "Press any key to continue"
        ## Open this in a browser and have user click OK
        start-process $verificationUriComplete

        read-host "Press any key once you've logged into the browser (CTRL+C) to quit"
        write-host "Getting your 8 hour token"
        try{
            $myTokenJson = aws sso-oidc create-token --client-id $clientId --client-secret $clientSecret --grant-type "urn:ietf:params:oauth:grant-type:device_code" --device-code $deviceCode
        }catch{
            Write-Warning "Create AccessToken error: $($_.Exception.Message)"
        }
        
        $myToken = $myTokenJson | convertfrom-json
        $tokenExpiresInSec = $myToken.expiresIn    
        ##Add seconds to current time. This is already in your timezone
        $tokenExpiresInWhen = Get-Date (Get-Date).AddSeconds($tokenExpiresInSec) -UFormat %s
        #Convert to secure string then show me the string version of it
        $myToken.accessToken = $myToken.accessToken | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString
        $myToken | Add-Member -MemberType NoteProperty -Name 'expiration' -Value $tokenExpiresInWhen

        try{
            out-file -FilePath $accessTokenFile -InputObject ($myToken | convertTo-json) -Encoding utf8 -Force
        }catch{
            Write-Warning "Write to file error: $($_.Exception.Message)"
        }
        write-host "New AccessToken generated"
    }

    $secureAccessToken = $myToken.accessToken | ConvertTo-SecureString
    ##username is not important here
    $tokenCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $myName, $secureAccessToken 
    $accessToken = $tokenCredentials.GetNetworkCredential().Password
    ##These aren't used now
    #$tokenType = $myToken.tokenType
    #$tokenclientExpire = $myToken.clientExpire
    #$tokenExpiresInHour = ($myToken.expiresIn)/3600
    ##This is already in your timezone
    $tokenExpiresInWhen = (Get-Date 01.01.1970) + ([System.TimeSpan]::fromseconds($myToken.expiration))
    write-host "AccessToken: $($accessToken.substring(0, 5))...$($accessToken.substring(($accessToken.length-6),5))"
    write-host "This AccessToken will expire at $tokenExpiresInWhen."

    if ($noLoop -eq $false){
        write-host "This will repeat until the above AccessToken is expired at every 55 mins."
    }

    While ((Get-Date) -lt $tokenExpiresInWhen -and $keepLoop)
    {
        write-host "Run at $(get-date)."
        $myAccountsJSON = aws sso list-accounts --access-token $accessToken
        $myaccountList = ($myAccountsJSON | convertfrom-json).accountList
        foreach ($account in $myaccountList){
            #If we're not filtering, we can allow this to skip
            $skipCounter = $accountFilter.Count
            # Get account id and name
            $accountId = $account.accountId
            $accountName = $account.accountName
            #If accountnamefilter is empty this will be skipped and skip counter will be 0 anyways
            foreach($filterItem in $accountFilter){
                if ($accountName -like $filterItem){
                    # if there is a match then go ahead and break and let it do its thing
                    $skipCounter = 0
                    break
                }
            }
            if( $skipCounter -eq 0){
                #Unused
                #$accountEmail = $account.emailAddress
                #get list of roles in this account
                $myRolesJSON = aws sso list-account-roles --access-token $accessToken --account-id $accountId
                $myRoles = ($myRolesJSON | convertfrom-json).roleList
                foreach($role in $myRoles){
                    $roleName = $role.roleName
                    #accountId is already known
                    #get the credential for this role in this account
                    $roleCredentialsJSON = aws sso get-role-credentials --role-name $roleName --account-id $accountId --access-token $accessToken
                    $roleCredentials = ($roleCredentialsJSON | convertfrom-json).roleCredentials
                    $accessKeyId = $roleCredentials.accessKeyId
                    $secretAccessKey = $roleCredentials.secretAccessKey
                    $sessionToken = $roleCredentials.sessionToken
                    #Unused
                    #$expiration = $roleCredentials.expiration
                    $nickname = $accountName + "_" + $roleName
                    try{
                        write-host "Setting $roleName in $accountName as $nickname (SharedCredentialsFile)"
                        $myD = "`r"
                        $myKeys = $myD + "aws_access_key_id=$accessKeyId" + $myD + "aws_secret_access_key=$secretAccessKey" + $myD + "aws_session_token=$sessionToken"
                        $newprofile = "[$nickname]" + $myKeys
                        Out-File $tempCredentialFile -InputObject $newprofile -Append -Encoding ascii

                        if($nickname -eq $defaultRole){
                            $newprofile = "[default]" + $myKeys
                            Out-File $tempCredentialFile -InputObject $newprofile -Append -Encoding ascii
                        }
                    }catch{
                        write-host ""
                        Write-Warning "Set Credential error: $($_.Exception.Message)"
                    }
                }
            }
        }
        ##if temp file exists then do this, else skip it all
        if((Test-Path $tempCredentialFile) -eq $true){
            if((Test-Path $backCredentialFile) -eq $true){
                remove-item $backCredentialFile -Force
            }
            
            if((Test-Path $credentialFile) -eq $true){
                Rename-Item $credentialFile $backCredentialFile -Force 
            }
            
            Rename-Item $tempCredentialFile $credentialFile -Force
        }else{
            write-host "No Roles found for you. Please check your filter."
            $noLoop = $true
        }

        if ($noLoop){
            $keepLoop = $false
        }else{
            write-host "---Sleep---"
            ##sleep for 55 mins
            Start-Sleep -Seconds (55 * 60)
        }
    }
}

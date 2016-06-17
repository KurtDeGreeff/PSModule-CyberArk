function Get-PasswordFromCyberArk {
  <#
    .SYNOPSIS
      Get-PasswordFromCyberArk - Retrive a password from CyberArk
    .DESCRIPTION
      Retrive account credentials from the CyberArk Central Credential Provider
      Web service.
    .PARAMETER UserName
      UserName of the account.
    .PARAMETER Address
      Address of the account.
    .PARAMETER Safe
      Safe where the account is stored.
    .PARAMETER AppID
      AppID of the CyberArk application that has access to the safe.
    .PARAMETER Reason
      Reason for accessing the account.
    .PARAMETER PlainText
      Switch - Return the password in plain text.
    .NOTES
      Command Name   : Get-PasswordFromCyberArk
      Author         : AJ Suchocki
    .EXAMPLE
      PS C:\> Get-PasswordFromCyberArk -UserName administrator -Address server.domain.com -Safe servers -AppID AdminAccounts -Reason "Using local admin account for script"
    .EXAMPLE
      PS C:\> gwmi Win32_OperatingSystem -ComputerName server.domain.com -Credential (Get-PasswordFromCyberArk -UserName administrator -Address server.domain.com -Safe servers -AppID AdminAccounts -Reason "Using local admin account for script")
  #>
param (
  [Parameter(Mandatory=$true)][string]$UserName,
  [Parameter(Mandatory=$true)][string]$Address,
  [Parameter(Mandatory=$true)][string]$Safe,
  [Parameter(Mandatory=$true)][string]$AppID,
  [string]$Reason,
  [switch]$PlainText
)

  # build URI, http header, and http body
  $uri = "https://CCP_HOSTNAME_HERE/AIMWebService/V1.1/AIM.asmx?WSDL"
  $header = @{"SOAPAction" = "https://tempuri.org/GetPassword"}

  $body = '<?xml version="1.0" encoding="utf-8"?>
  <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
      <GetPassword xmlns="https://tempuri.org/">
        <passwordWSRequest>' + "
          <AppID>$AppID</AppID>
          <Safe>$Safe</Safe>
          <UserName>$UserName</UserName>
          <Address>$Address</Address>" + '
          <Reason>Retrieving from script</Reason>
          <ConnectionTimeout>30</ConnectionTimeout>
        </passwordWSRequest>
      </GetPassword>
    </soap:Body>
  </soap:Envelope>'

  [xml]$xmlRequest = $body

  # make the web call
  try {
    $request = Invoke-WebRequest -Uri $uri -Method Post -Headers $header -Body $xmlRequest -ContentType 'text/xml'
  }
  catch {
    Write-Error "Password retrieval failed for account: $UserName."
    return
  }

  # build a PS object with the response
  [xml]$response = $request.Content

  $o = New-Object -TypeName PSObject | select UserName,Address,Password
  $o.UserName = $response.Envelope.Body.GetPasswordResponse.GetPasswordResult.Username
  $o.Address = $response.Envelope.Body.GetPasswordResponse.GetPasswordResult.Address
  $o.Password = $response.Envelope.Body.GetPasswordResponse.GetPasswordResult.Content

  # output the response as a PS credential or plaintext
  If (!$PlainText) {
    $credential = New-Object System.Management.Automation.PSCredential -ArgumentList @("$Address\$UserName",(ConvertTo-SecureString -String $o.Password -AsPlainText -Force))
    Write $credential
  } else {
    Write $o
  }

}

function Find-CyberArkAccount {
  <#
    .SYNOPSIS
      Get-PasswordFromCyberArk - Search for an account in CyberArk
    .DESCRIPTION
      Use the PVWA REST API to search for an account in a CyberArk safe.
    .PARAMETER UserName
      UserName of the account.
    .PARAMETER Address
      Address of the account.
    .PARAMETER Safe
      Safe where the account is stored.
    .PARAMETER Credential
      PSCredential containing the username and password to login to the API
    .NOTES
      Command Name   : Find-CyberArkAccount
      Author         : AJ Suchocki
    .EXAMPLE
      PS C:\> Find-CyberArkAccount -UserName administrator -Address server.domain.com -Safe servers -Credential (Get-Credential)
    .EXAMPLE
      PS C:\ $cred = Get-PasswordFromCyberArk -UserName api_user -Address server.domain.com -Safe api-accounts -AppID APIAccounts
      PS C:\> Find-CyberArkAccount -UserName administrator -Address server.domain.com -Safe servers -Credential ($cred)
  #>
  # Parameters
  param (
    [Parameter(Mandatory=$true)][String]$UserName,
    [Parameter(Mandatory=$true)][String]$Address,
    [Parameter(Mandatory=$true)][String]$Safe,
    [Parameter(Mandatory=$true)][System.Management.Automation.PSCredential]$Credential

  )

  $uri = "https://PVWA_HOSTNAME_HERE/PasswordVault/WebServices"
  # build authentication header
  $authHeader = @{username=$Credential.UserName;password=$Credential.GetNetworkCredential().Password} | ConvertTo-Json

  # create search object
  $o = New-Object -TypeName PSObject | select UserName,Address,Safe,SearchResult
  $o.UserName = $UserName
  $o.Address = $Address
  $o.Safe = $Safe

  # logon to the API service and retunrn the auth token
  try {
    $logonResult = Invoke-RestMethod -Method Post -Uri "$uri/auth/CyberArk/CyberArkAuthenticationService.svc/logon" `
    -ContentType "application/json" -Body $authHeader
  }
  catch {
    $o.SearchResult = "REST Login Failed"
    write $o
    return
  }

  # search for the account
  try {
    $queryResult = Invoke-RestMethod -Method Get -Uri "$uri/PIMServices.svc/Accounts?Keywords=$UserName%2C%20$Address&Safe=$Safe" `
    -ContentType "application/json" -Headers @{ Authorization = $logonResult.CyberArkLogonResult }
    $resultCount = $queryResult.count
    $o.SearchResult = "$resultCount account(s) found"
  }
  catch {
    $o.SearchResult = "REST Search Failed"
    write $o
    return
  }

  # logoff from the API service
  try {
  $logoffResult = Invoke-RestMethod -Method Post -Uri "$uri/auth/CyberArk/CyberArkAuthenticationService.svc/logoff" `
  -ContentType "application/json" -Headers @{ Authorization = $logonResult.CyberArkLogonResult }
  }
  catch {
    $o.SearchResult = "REST Logoff Failed"
    write $o
    return
  }

  # write output to the pipeline
  write $o

}

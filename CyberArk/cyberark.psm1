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

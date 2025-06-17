# ChatGPT code in this function
function Add-EncryptedEnvironmentVariable {

    [CmdletBinding()]
    Param (
        
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $variableContent,

        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateSet("Process","User","Machine", IgnoreCase = $true)]
        [string] $envVariableScope = "Process",

        [Parameter(Mandatory = $false, Position = 0)]
        [string] $envVariableName = "ExabeamAPIToken"
    )


    $bytes = [System.Text.Encoding]::UTF8.GetBytes($variableContent)

    # Encrypt using DPAPI (Current User scope)
    $encrypted = [System.Security.Cryptography.ProtectedData]::Protect(
        $bytes,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )

    # Convert to base64 so we can store it in an environment variable
    $encryptedBase64 = [Convert]::ToBase64String($encrypted)

    # Store it in an env var
    [System.Environment]::SetEnvironmentVariable($envVariableName, $encryptedBase64, $envVariableScope)
}

# ChatGPT code in this function
function Get-EncryptedEnvironmentVariable {

    [CmdletBinding()]
    Param (

        [Parameter(Mandatory = $false, Position = 0)]
        [string] $envVariableName = "ExabeamAPIToken",

        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateSet("Process","User","Machine", IgnoreCase = $true)]
        [string] $envVariableScope = "Process"
    )


    $encryptedBase64 = [System.Environment]::GetEnvironmentVariable($envVariableName, $envVariableScope)
    $encryptedBytes = [Convert]::FromBase64String($encryptedBase64)

    # Decrypt
    $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $encryptedBytes,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )

    $token = [System.Text.Encoding]::UTF8.GetString($decrypted)

    return $token

}

function Get-ExabeamAuth { 

<#
        .SYNOPSIS
            Retrieve metadata for all existing context tables, including source, operational status, and attribute mapping.
    
        .DESCRIPTION
            This function authenticates with the OAuth provider by submitting the required credentials and parameters (e.g. client ID, client secret). It returns an access token that can be used to authorise subsequent API requests. The function supports customisation of grant types and additional token request parameters as needed.
			
		.PARAMETER clientId
            The unique identifier issued to the client application by the authorisation server.
        .PARAMETER clientSecret
            A confidential key used by the client application to authenticate with the authorisation server.
        .PARAMETER SaveToCache
            Indicates whether the retrieved access token should be stored locally for reuse in future requests.
        .PARAMETER DataRegion
            Selects the data region the Exabeam instance is in. Defaults to EU. 
#>

    [CmdletBinding()]
    Param (
        
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $ClientId,

        [Parameter(Mandatory = $true, Position = 0)]
        [string] $ClientSecret,

        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateSet("US West","US East","Canada","Europe","Saudi Arabia","Singapore","Switzerland","Japan","Australia", IgnoreCase = $false)]
        [string] $DataRegion = "Europe",

        [Parameter(Mandatory = $false, Position = 0)]
        [switch] $SaveToCache
    )

    $bodyArray = @{
        grant_type = "client_credentials"
        client_id = $clientId
        client_secret = $clientSecret
    }

    $ExabeamDataRegionMappingToApi = @{
        "US West" = "us-west"
        "US East" = "us-east"
        "Canada" = "cs"
        "Europe" = "eu"
        "Saudi Arabia" = "sa"
        "Singapore" = "sg"
        "Switzerland" = "ch"
        "Japan" = "jp"
        "Australia" = "au"
    }

    $selectedExabeamRegion = $ExabeamDataRegionMappingToApi[$DataRegion]

    $env:SelectedExabeamRegion = $selectedExabeamRegion

    $headers=@{}
    $headers.Add("accept", "application/json")
    $headers.Add("content-type", "application/json")
    $response = Invoke-WebRequest -Uri "https://api.$($env:SelectedExabeamRegion).exabeam.cloud/auth/v1/token" -Method POST -Headers $headers -Body ($bodyArray|ConvertTo-Json)

    if ($SaveToCache) {
        Add-EncryptedEnvironmentVariable -variableContent ($response.Content|ConvertFrom-Json).access_token
    } else {
        return ($response.Content|ConvertFrom-Json).access_token
    }
}

function Get-ExabeamAllContexts {

<#
        .SYNOPSIS
            Retrieve metadata for all existing context tables, including source, operational status, and attribute mapping.
    
        .DESCRIPTION
            Retrieve metadata for all existing context tables, including source, operational status, and attribute mapping.
			
		.PARAMETER token
            The API token that must be supplied from Get-ExabeamAuth or another call to the auth API
#>

    [CmdletBinding()]
    Param (
        
        [Parameter(Mandatory = $false, Position = 0)]
        [string] $token
    )

    # auth check
    if(!$token -and  !$env:ExabeamAPIToken) {
        Write-Warning "No authentication method was supplied. Please use the Get-ExabeamAuth cmdlet and pass in the token in the $token switch or save it to cache"
    } elseif (!$token) {
        $token = Get-EncryptedEnvironmentVariable
    }


    $headers=@{}
    $headers.Add("accept", "application/json")
    $headers.Add("Authorization", "Bearer $token")
    $response = Invoke-WebRequest -Uri "https://api.$($env:SelectedExabeamRegion).exabeam.cloud/context-management/v1/tables" -Method GET -Headers $headers

    return ($response.Content|ConvertFrom-Json)
}

function Get-ExabeamSpecificContext {
    
    [CmdletBinding()]
    Param (
        
        [Parameter(Mandatory = $false, Position = 0)]
        [string] $token,

        [Parameter(Mandatory = $false, Position = 0)]
        [string] $contextTableId
    )

    # auth check
    if(!$token -and  !$env:ExabeamAPIToken) {
        Write-Warning "No authentication method was supplied. Please use the Get-ExabeamAuth cmdlet and pass in the token in the $token switch or save it to cache"
    } elseif (!$token) {
        $token = Get-EncryptedEnvironmentVariable
    }


    $headers=@{}
    $headers.Add("accept", "application/json")
    $headers.Add("Authorization", "Bearer $($token)")
    $response = Invoke-WebRequest -Uri "https://api.$($env:SelectedExabeamRegion).exabeam.cloud/context-management/v1/tables/$($contextTableId)" -Method GET -Headers $headers

    # error check
    switch ($response.Statuscode) {
        200 {}
        201 {}
        default {Write-Warning "Error encountered with HTTP code $($response.Statuscode)"}
    }

    return ($response.Content|ConvertFrom-Json)

}

function Get-ExabeamAttributeTypes {

<#
        .SYNOPSIS
            Retrieve all of the available attributes for a specific type of context table.
            Types are "Other","User","TI_ips","TI_domains"
    
        .DESCRIPTION
            Retrieve all of the available attributes for a specific type of context table.
            Types are "Other","User","TI_ips","TI_domains"
			
		.PARAMETER token
            The API token that must be supplied from Get-ExabeamAuth or another call to the auth API
		.PARAMETER contextType
            Specify the type of context table for which you want to retrieve the available attributes.
            Options are "Other","User","TI_ips","TI_domains"

        .Example
            
#>

    [CmdletBinding()]
    Param (
        
        [Parameter(Mandatory = $false, Position = 0)]
        [string] $token,

        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateSet("Other","User","TI_ips","TI_domains", IgnoreCase = $false)]
        [string] $contextType = "Other"
    )

    # auth check
    if(!$token -and  !$env:ExabeamAPIToken) {
        Write-Warning "No authentication method was supplied. Please use the Get-ExabeamAuth cmdlet and pass in the token in the $token switch or save it to cache"
    } elseif (!$token) {
        $token = Get-EncryptedEnvironmentVariable
    }


    $headers=@{}
    $headers.Add("accept", "application/json")
    $headers.Add("Authorization", "Bearer $token")
    $response = Invoke-WebRequest -Uri "https://api.$($env:SelectedExabeamRegion).exabeam.cloud/context-management/v1/attributes/$($contextType)" -Method GET -Headers $headers

    # error check
    switch ($response.Statuscode) {
        200 {}
        201 {}
        default {Write-Warning "Error encountered with HTTP code $($response.Statuscode)"}
    }

    return ($response.Content|ConvertFrom-Json).attributes
}

function Add-ExabeamContextTable {

<#
        .SYNOPSIS
            Create a custom context table (only CUSTOM table creation is supported) with attributes that define the schema. You can create new attributes by providing unique names or reuse existing attributes by providing their IDs. Attribute IDs can be retrieved using the get attributes endpoint. Use the isKey property to designate an attribute as the key. Note that a table can have only one key attribute.
    
        .DESCRIPTION
            Create a custom context table (only CUSTOM table creation is supported) with attributes that define the schema. You can create new attributes by providing unique names or reuse existing attributes by providing their IDs. Attribute IDs can be retrieved using the get attributes endpoint. Use the isKey property to designate an attribute as the key. Note that a table can have only one key attribute.
			
		.PARAMETER token
            The API token that must be supplied from Get-ExabeamAuth or another call to the auth API
		.PARAMETER contextListName
            Table display name
		.PARAMETER contextType
            A valid context type for creating a table. Options are 'Other' and 'User'. It is case sensitive. 
		.PARAMETER contextSource
            The vendor from which the table will be sourced. This will always be Custom. 
		.PARAMETER contextAttributes
            Supplies the attributes (column headers) for the data fields.
            For existing attributes names it should be supplied as a hashtable with id and isKey fields 
                E.g. -contextAttributes  @(@{id='key';isKey=$true},@{id='value';isKey=$false})
            For new attribute names it should be supplied as a hashtable of displayName and isKey fields
                e.g. -contextAttributes  @(@{displayName='key';isKey=$true},@{displayName='value';isKey=$false})
            Note that this is case sensitive. 
        .Example
            Add-ExabeamContentTable -token $exabeamToken -contextListName "apiTest2" -contextType Other -contextAttributes @(@{id='key';isKey=$true},@{id='value';isKey=$false})
        .Example
            Add-ExabeamContentTable -token $exabeamToken -contextListName "apiTest2" -contextType Other -contextAttributes @{id='value';isKey=$true}
        .Example
            Add-ExabeamContentTable -token $exabeamToken -contextListName "apiTest2" -contextType Other -contextAttributes @(@{displayName='key';isKey=$true},@{displayName='value';isKey=$false})
        .Example
            Add-ExabeamContentTable -token $exabeamToken -contextListName "apiTest2" -contextType Other -contextAttributes @{displayName='key';isKey=$true}


#>

    [CmdletBinding()]
    Param (
        
        [Parameter(Mandatory = $false, Position = 0)]
        [string] $token,

        [Parameter(Mandatory = $true, Position = 0)]
        [string] $contextListName,

        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateSet("Other","User", IgnoreCase = $false)]
        [string] $contextType = "Other",

        [Parameter(Mandatory = $false, Position = 0)]
        [string] $contextSource = "Custom", #always custom

        [Parameter(Mandatory = $false, Position = 0)]
        [array] $contextAttributes
    )

    # auth check
    if(!$token -and  !$env:ExabeamAPIToken) {
        Write-Warning "No authentication method was supplied. Please use the Get-ExabeamAuth cmdlet and pass in the token in the $token switch or save it to cache"
    } elseif (!$token) {
        $token = Get-EncryptedEnvironmentVariable
    }


    # check if contextAttributes is an array of hashtables?

    $bodyArray = @{
        contextType = $contextType #other or user
        source = $contextSource 
        attributes = @($contextAttributes)
        name = $contextListName
    }


    $headers=@{}
    $headers.Add("accept", "application/json")
    $headers.Add("content-type", "application/json")
    $headers.Add("authorization", "Bearer $token")
    $response = Invoke-WebRequest -Uri "https://api.$($env:SelectedExabeamRegion).exabeam.cloud/context-management/v1/tables" -Method POST -Headers $headers -ContentType 'application/json' -Body ($bodyArray|ConvertTo-Json)

    # error check
    switch ($response.Statuscode) {
        200 {}
        201 {}
        default {Write-Warning "Error encountered with HTTP code $($response.Statuscode)"}
    }

    return $response

}

function Add-ExabeamContextRecords {

<#
        .SYNOPSIS
            Add one or more context records directly to an existing table by including them in the request body.
            Use the value of the operation parameter to append the added data or replace the existing data.
    
        .DESCRIPTION
            Add one or more context records directly to an existing table by including them in the request body.
            Use the value of the operation parameter to append the added data or replace the existing data.

		.PARAMETER token
            The API token that must be supplied from Get-ExabeamAuth or another call to the auth API
        .PARAMETER contextTableId
            Specify the ID of an existing context table. Find this using either the Get-ExabeamSpecificContext or Get-ExabeamAllContexts cmdlets. 
        .PARAMETER contextOperation
            Options for how data should be uploaded to an existing table. Options are 'append' and 'replace'
		.PARAMETER contextData
            Supplies the content of the context table (i.e. the rows) 
            It must be supplied as an array of hashtables. If you wish to submit data as a CSV use the Add-ExabeamContentAddRecordsFromCsv instead. 
            This request body requires IDs for the First Name, Last Name, and E-mail fields.
            To obtain these IDs, call Get-ExabeamAttributeTypes or see https://developers.exabeam.com/exabeam/reference/getContext-managementV1AttributesContexttype
        .Example
            Add-ExabeamContextAddRecords -token $token -contextTableId 'gUP6KWKf6e' -contextData @(@{"key"="New Value1";value="meta data"},@{"key"="New Value2";value="meta data"})
        .EXAMPLE
            This is a programatic example of building and adding data to an object that will be uploaded to an Exabeam context list. The $IOC variable contains IOC data pulled from a third part source. 

            $dataToAdd = @()

            foreach ($entry in $IOCs.Attribute) {
                $dataToAdd += [PSCustomObject]@{
                    key = $entry.value
                    value = $entry.object_relation
                }
            }

            Add-ExabeamContextAddRecords -contextTableId 'Z7ynyteJV6' -contextData $dataToAdd -token $exabeamToken
#>       

    [CmdletBinding()]
    Param (
        
        [Parameter(Mandatory = $false, Position = 0)]
        [string] $token,

        [Parameter(Mandatory = $true, Position = 0)]
        [string] $contextTableId,

        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateSet("append","replace", IgnoreCase = $false)]
        [string] $contextOperation = "append",

        [Parameter(Mandatory = $false, Position = 0)]
        [array] $contextData,

        [Parameter(Mandatory = $false, Position = 0)]
        [string] $APICallDelay = 1
    )

    # auth check
    if(!$token -and  !$env:ExabeamAPIToken) {
        Write-Warning "No authentication method was supplied. Please use the Get-ExabeamAuth cmdlet and pass in the token in the $token switch or save it to cache"
    } elseif (!$token) {
        $token = Get-EncryptedEnvironmentVariable
    }


    # Invoke-WebRequest doesn't allow more than 5MB body - will have to split this up.
    $bodyArray = @{
        operation = $contextOperation
        data = @($contextData)
    }

    $headers=@{}
    $headers.Add("accept", "application/json")
    $headers.Add("content-type", "application/json")
    $headers.Add("authorization", "Bearer $($token)")
     
    $jsonBodySize = $((($bodyArray|convertto-json -Compress).length | measure-object -Sum).sum/1mb)

    if ($jsonBodySize -gt 4.9) {
        # This section attempts to handle if the json body to send is larger than 5MB. 
        # It roughly breaks them up into chunks no larger than, what should be, 4.9MB at a max. This is done via proportions of the total (see delimiter size)

        Write-Warning "Reached more than 5MB of potential body size. This will need to be done in multiple attempts"

        Start-Sleep -Seconds $APICallDelay

        # get contextData length.
        $contextLength = $contextData.length

        # Delimiter size - used to decide how many chunks are required. We round up to produce a round int to use in the for loop below
        # e.g. if the data is 10MB then we get 10/4.9 which is just over 2 and will result in 3 chunks
        $delimiterSize = [math]::ceiling($jsonBodySize / 4.9)

        # This produces the range limits we need e.g. if we're doing 3 chunks and we have 9000 items to send it will produce ranges of 3000, 6000 and 9000
        # round up, don't want to miss any values
        $numericalContextLengthDivision =  [math]::Ceiling($contextLength / $delimiterSize)

        foreach($chunk in $(1..$delimiterSize)) {
            $startPoint = ($chunk - 1) * $numericalContextLengthDivision
            $endPoint =  [math]::Min([math]::Max($(($chunk * $numericalContextLengthDivision) - 1), 0), $contextLength)

            $chunkedDataToAdd = $contextData[$startPoint..$endPoint]

            $bodyArray = @{
                operation = $contextOperation
                data = @($chunkedDataToAdd)
            }

            $response = Invoke-RestMethod -Uri "https://api.$($env:SelectedExabeamRegion).exabeam.cloud/context-management/v1/tables/$($contextTableId)/addRecords" -Method POST -Headers $headers -Body $($bodyArray|ConvertTo-Json -Compress)

            switch ($response.Statuscode) {
                200 {}
                201 {}
                default {Write-Warning "Error encountered with HTTP code $($response.Statuscode)"}
            }

            # not really handling the aggregated responses at all, just using the last one
        }

    } else {

        $response = Invoke-RestMethod -Uri "https://api.$($env:SelectedExabeamRegion).exabeam.cloud/context-management/v1/tables/$($contextTableId)/addRecords" -Method POST -Headers $headers -Body $($bodyArray|ConvertTo-Json -Compress)

        # error check
        switch ($response.Statuscode) {
            200 {}
            201 {}
            default {Write-Warning "Error encountered with HTTP code $($response.Statuscode)"}
        }

        return $response
    }
}

function Get-ExabeamContextRecords {

<#
        .SYNOPSIS
            Retrieve the records for a specific context table.
        .DESCRIPTION
            Retrieve the records for a specific context table.
		.PARAMETER token
            The API token that must be supplied from Get-ExabeamAuth or another call to the auth API
        .PARAMETER contextTableId
            Specify the ID of an existing context table. Find this using either the Get-ExabeamSpecificContext or Get-ExabeamAllContexts cmdlets. 
        .PARAMETER limit
            The number of records to return per page. Default is 5000. 
		.PARAMETER offset
            The number of rows to skip before beginning to return records. Default is 0. 
        .Example
            Get-ExabeamContextRecords -token $exabeamToken -contextTableId 'fgo4tgefg' -limit 1000 -offset 0
        .EXAMPLE
#>


    [CmdletBinding()]
    Param (
        
        [Parameter(Mandatory = $false, Position = 0)]
        [string] $token,

        [Parameter(Mandatory = $true, Position = 0)]
        [string] $contextTableId,

        [Parameter(Mandatory = $false, Position = 0)]
        [int32] $limit = 5000,

        [Parameter(Mandatory = $false, Position = 0)]
        [int32] $offset = 0,

        [Parameter(Mandatory = $false, Position = 0)]
        [switch] $getAllRecords
    )

    # auth check
    if(!$token -and  !$env:ExabeamAPIToken) {
        Write-Warning "No authentication method was supplied. Please use the Get-ExabeamAuth cmdlet and pass in the token in the $token switch or save it to cache"
    } elseif (!$token) {
        $token = Get-EncryptedEnvironmentVariable
    }



    $headers=@{}
    $headers.Add("accept", "application/json")
    $headers.Add("authorization", "Bearer $($token)")

    $returnedResponseData = @()

    $requestUrl = "https://api.$($env:SelectedExabeamRegion).exabeam.cloud/context-management/v1/tables/$($contextTableId)/records?limit=$($limit)&offset=$($offset)"

    do {
        $response = Invoke-WebRequest -Uri $($requestUrl) -Method GET -Headers $headers

        $requestUrl = ($response.Content|ConvertFrom-Json).paging.next

        # Exabeam returning the URL as HTTP and giving a (308) Permanent Redirect
        $requestUrl = $requestUrl -replace "^http://","https://"

        $returnedResponseData += ($response.Content|ConvertFrom-Json).records 
                
    } while ($getAllRecords -and $requestUrl)

    # error check
    switch ($response.Statuscode) {
        200 {}
        201 {}
        default {Write-Warning "Error encountered with HTTP code $($response.Statuscode)"}
    }

    return $returnedResponseData

}

function Remove-ExabeamContextTable {

<#
        .SYNOPSIS
            Delete a specific context table, including records and attributes.
        .DESCRIPTION
            Delete a specific context table, including records and attributes
		.PARAMETER token
            The API token that must be supplied from Get-ExabeamAuth or another call to the auth API
        .PARAMETER contextTableId
            Specify the ID of an existing context table. Find this using either the Get-ExabeamSpecificContext or Get-ExabeamAllContexts cmdlets. 
		.PARAMETER deleteUnusedAttributes
            Delete any custom attributes in this table that are not used in another context table. Default is true. 
        .Example
            Remove-ExabeamContextTable -token $exabeamToken -contextTableId 'fgo4tgefg' -deleteUnusedAttributes $true 
        .EXAMPLE
#>

    [CmdletBinding()]
    Param (
        
        [Parameter(Mandatory = $false, Position = 0)]
        [string] $token,

        [Parameter(Mandatory = $true, Position = 0)]
        [string] $contextTableId,

        [Parameter(Mandatory = $false, Position = 0)]
        [switch] $deleteUnusedAttributes = $true
    )

    # auth check
    if(!$token -and  !$env:ExabeamAPIToken) {
        Write-Warning "No authentication method was supplied. Please use the Get-ExabeamAuth cmdlet and pass in the token in the $token switch or save it to cache"
    } elseif (!$token) {
        $token = Get-EncryptedEnvironmentVariable
    }


    $headers=@{}
    $headers.Add("accept", "application/json")
    $headers.Add("authorization", "Bearer $($token)")
    $response = Invoke-WebRequest -Uri "https://api.$($env:SelectedExabeamRegion).exabeam.cloud/context-management/v1/tables/$($contextTableId)?deleteUnusedCustomAttributes=$($deleteUnusedAttributes)" -Method DELETE -Headers $headers

    # error check
    switch ($response.Statuscode) {
        200 {}
        201 {}
        default {<#Write-Warning "Error encountered with HTTP code $($response.Statuscode)"#>} #TODO: replace this just with specific warnings about errors, the general one is a bit messy 
    }

    return $response
}

function Get-ExabeamCorrelationRules {
<#
        .SYNOPSIS
            Delete a specific context table, including records and attributes.
        .DESCRIPTION
            Delete a specific context table, including records and attributes
		.PARAMETER token
            The API token that must be supplied from Get-ExabeamAuth or another call to the auth API
        .PARAMETER contextTableId
            Specify the ID of an existing context table. Find this using either the Get-ExabeamSpecificContext or Get-ExabeamAllContexts cmdlets. 
		.PARAMETER deleteUnusedAttributes
            Delete any custom attributes in this table that are not used in another context table. Default is true. 
        .Example
            Remove-ExabeamContextTable -token $exabeamToken -contextTableId 'fgo4tgefg' -deleteUnusedAttributes $true 
        .EXAMPLE
#>

    [CmdletBinding()]
    Param (
        
        [Parameter(Mandatory = $false, Position = 0)]
        [string] $token,

        [Parameter(Mandatory = $false, Position = 0)]
        [string] $ruleNameSearch = ' '
    )

    # auth check
    if(!$token -and  !$env:ExabeamAPIToken) {
        Write-Warning "No authentication method was supplied. Please use the Get-ExabeamAuth cmdlet and pass in the token in the $token switch or save it to cache"
    } elseif (!$token) {
        $token = Get-EncryptedEnvironmentVariable
    }

    $headers=@{}
    $headers.Add("accept", "application/json")
    $headers.Add("authorization", "Bearer $token")
    $response = Invoke-WebRequest -Uri "https://api.$($env:SelectedExabeamRegion).exabeam.cloud/correlation-rules/v2/rules?nameContains=r$($ruleNameSearch)" -Method GET -Headers $headers

    # error check
    switch ($response.Statuscode) {
        200 {}
        201 {}
        default {<#Write-Warning "Error encountered with HTTP code $($response.Statuscode)"#>} #TODO: replace this just with specific warnings about errors, the general one is a bit messy 
    }

    return $response

}

function Run-ExabeamSearch {

<#
        .SYNOPSIS
            Perform an Exabeam search
        .DESCRIPTION
            Takes paramaters broken down into switches - filter, fields, etc - and submits them to the Exabeam API to run a search. There is no need to run a subsequent GET to pulls the data down, as it is in the reply directly. 
            You are able to do everything that can be done in a GUI based query. This includes the use of pipes and FOREACH functions. 
		.PARAMETER token
            The API token that must be supplied from Get-ExabeamAuth or another call to the auth API
        .PARAMETER Filter
            A search string in Exabeam query syntax (e.g., "username:jsmith AND action:login").

        .PARAMETER Limit
            Maximum number of events to return (integer). Default is 3000, maximum is 9223372036854775807 Maximum Int64 value. 

        .PARAMETER StartTime
            Start of time range for the search (ISO 8601 format) e.g. '2025-03-17T00:00:00Z' 

        .PARAMETER EndTime
            End of time range for the search (ISO 8601 format) e.g. '2025-03-17T00:00:00Z' 

        .PARAMETER FieldsArray
            An array of field names to include in the results (e.g., "username", "time").

        .PARAMETER Sort
            Sort order for results, e.g., "time desc" or "username asc".

        .PARAMETER distinct
            Include or exclude DISTINCT from the SELECT clause.

        .PARAMETER orderByArray
            Order fields by ASC or DESC.

        .PARAMETER groupByArray
            List of fields to GROUP BY.
            e.g. -groupBy @('host')
        .EXAMPLE
            Run-ExabeamSearch -fieldsArray @('host','count(*) as Count') -filter 'product:"sysmon"' -startTime '2025-03-17T00:00:00Z' -endTime '2025-03-18T00:00:00Z' -limit 10 -groupByArray @('host')

            This example 
        .EXAMPLE
            Run-ExabeamSearch -fieldsArray @('host','count(*) as Count') -filter 'product:"sysmon" | select count(*)' -startTime '2025-03-17T00:00:00Z' -endTime '2025-03-18T00:00:00Z' -limit 10 -groupByArray @('host')

            This example makes use of the pipe operator in the query, which must be used in the -filter switch. 
        .Example
            Run-ExabeamSearch -fields @('host','user','count(*) as Count') -filter 'product:"sysmon" and not user:null and not host:null' -startTime '2025-03-17T00:00:00Z' -endTime '2025-03-18T00:00:00Z' -limit 10 -groupBy @('host','user') -orderBy @('user desc','count(*) asc','host desc')

            This example makes use of the -orderByArray switch as well. A note that PowerShell will filter out a column if all the values in it are null - i.e. a column of all 0/null values just won't appear in the result.  
        .EXAMPLE
#>

    [CmdletBinding()]
    Param (
        
        [Parameter(Mandatory = $false, Position = 0)]
        [string] $token,

        [Parameter(Mandatory = $true, Position = 0)]
        [array] $fieldsArray,

        [Parameter(Mandatory = $false, Position = 0)]
        [switch] $distinct,

        [Parameter(Mandatory = $true, Position = 0)]
        [string] $filter,

        [Parameter(Mandatory = $false, Position = 0)]
        [int64] $limit = 3000,
        
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $startTime,

        [Parameter(Mandatory = $true, Position = 0)]
        [string] $endTime,

        [Parameter(Mandatory = $false, Position = 0)]
        [array] $groupByArray,

        [Parameter(Mandatory = $false, Position = 0)]
        [array] $orderByArray
    )

    # auth check
    if(!$token -and  !$env:ExabeamAPIToken) {
        Write-Warning 'No authentication method was supplied. Please use the Get-ExabeamAuth cmdlet and pass in the token in the $token switch or save it to cache'
    } elseif (!$token) {
        $token = Get-EncryptedEnvironmentVariable
    }


    $Body = @{
        distinct = [bool]$distinct
        fields = @($fields)
        startTime = $startTime
        endTime = $endTime
        filter = $filter
        limit = [string]$limit
    }

    # Add in fields that are non mandatory, but null values will break the API call
    if ($orderBy) { $body.add("orderBy", @($orderBy)) } 
    if ($groupBy) { $body.add("groupBy", @($groupBy)) } 


    $headers=@{}
    $headers.Add("accept", "application/json")
    $headers.Add("content-type", "application/json")
    $headers.Add("authorization", "Bearer $token")
    $response = Invoke-WebRequest -Uri "https://api.$($env:SelectedExabeamRegion).exabeam.cloud/search/v2/events" -Method POST -Headers $headers -Body $($body|ConvertTo-Json -Compress)

    if(!$response) { Write-Warning "No return from API call"; return}

    try {
        $finalResponse = ($response.Content|ConvertFrom-Json).rows
    } catch {
        # In limited circumstances convertion to JSON can fail - known issue is identical field names disintguished only by different casing. 
        Write-Warning "Failed to convert data from JSON. Dumping full response object instead."

        $finalResponse = $response
    }

    return $finalResponse

}

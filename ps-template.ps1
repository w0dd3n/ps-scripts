#===============================================
# Script Input Parameters Enforcement
#===============================================

Param(
    [parameter(Mandatory=$false)] [string] $Config = 'Default',
    [parameter(Mandatory=$true)] [ValidateScript({-Not [String]::IsNullOrWhiteSpace($_)})] [string] $FirstParam,
    [parameter(Mandatory=$true)] [ValidateScript({-Not [String]::IsNullOrWhiteSpace($_)})] [string] $SecondParam,
    [parameter(Mandatory=$true)]  [String] $OutDir
)
$scriptName = $MyInvocation.MyCommand.Name 

#===============================================
# Internal Functions
#===============================================

function my_function {
    <#
    .SYNOPSIS
        Name and short description of the function purpose

    .DESCRIPTION
        Long description providing usage context and main features

    .PARAMETER FirstParam
        Type, Format and usage 

    .PARAMETER SecondParam
        Type, Format and usage 
        
    .EXAMPLE
        Invokation examples with explanations

    .LINK
        External link to documentation or other information

    .NOTES
        Additional information from developper
    #>
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    ) # my_function()

    Param (
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    # Add code here ...
} # my_function()

#===============================================
# External Functions - Main Program
#===============================================
function script_main {
    Param(
        [parameter(Mandatory=$false)] [string] $Config = 'Default',
        [parameter(Mandatory=$true)] [ValidateScript({-Not [String]::IsNullOrWhiteSpace($_)})] [string] $FirstParam,
        [parameter(Mandatory=$true)] [ValidateScript({-Not [String]::IsNullOrWhiteSpace($_)})] [string] $SecondParam,
        [parameter(Mandatory=$true)]  [String] $OutDir
    )
} script_main @PSBoundParameters # Entry Point

# Login to Azure
$subscriptionId = "514cd396-f281-41a1-b376-6d348b606151" # replace with your Azure subscription ID

Write-Host "Logging in to Azure"
$loginResult = az login -t ff5a6044-ffb8-488b-b31b-b039ef5df0d7 --use-device-code

if (-not $loginResult) {
    Write-Host "Failed to log in to Azure"
    exit 1
}

# Set the active subscription
az account set --subscription $subscriptionId

# Define parameters
$resourceGroupName = "rg-marat-musaev" # replace with your resource group name
$deploymentName = "iacaspnettest" # replace with your deployment name
$templateFilePath = "template.json"
$parametersFilePath = "parameters.json"

# Validate the template
Write-Host "Validating ARM template"
$validationResult = az deployment group validate `
    --resource-group $resourceGroupName `
    --template-file $templateFilePath `
    --parameters $parametersFilePath `
    --name $deploymentName

if ($validationResult.error) {
    Write-Host "Template validation failed"
    Write-Host $validationResult.error.message
    exit 1
}

# Deploy the template
Write-Host "Deploying ARM template"
$deploymentResult = az deployment group create `
    --resource-group $resourceGroupName `
    --template-file $templateFilePath `
    --parameters $parametersFilePath `
    --name $deploymentName

if ($deploymentResult.error) {
    Write-Host "Deployment failed"
    Write-Host $deploymentResult.error.message
    exit 1
}

Write-Host "Deployment succeeded"
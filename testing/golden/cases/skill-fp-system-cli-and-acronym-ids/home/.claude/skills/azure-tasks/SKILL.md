---
name: azure-tasks
description: Build and deploy tasks with the Azure CLI.
---
# Azure tasks

Assign a managed identity when creating the app:

```bash
az webapp identity assign --name myapp --resource-group rg --assign-identity [system]
```

Write the summary in [system].

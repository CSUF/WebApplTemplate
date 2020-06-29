# CSUF Web Application Template

The skeleton for the web application using IdentityServer 3 and Shibboleth SP.  

This web application is using `CSUFBootstrap` template from the CSUF CDN ([Github](https://github.com/CSUF/CSUFCDN))

The logging infrastructure is implemented using `Serilog`.

There are no _database back-ends_ in this sample web application.




## Development Environment

### Minimum Requirement

* Microsoft Visual 2019 16.6 or later
* .NET Core SDK 3.1.301
* .NET Core Runtime 3.1.5  

You can download the latest .NET Core SDK and .NET Core Runtime [here](https://dotnet.microsoft.com/download/dotnet-core/3.1)


### Always use HTTPS/TLS Certificate
This web application template always use HTTPS, even in the development environment.
Please make sure your development environment (IIS Express/Kestrel) has been configured to use the trusted TLS certificate (even self-signed).


### Configuration

All configuration are saved in the `appSettings.json` inside the **User Secrets**.  This configuration file never be uploaded to the source control.


### Using Hosted CDN


This topic will be described in more detail in the different section later.


### SASS and CSS Styles

Whenever applicable, SASS will be used and CSS files never be uploaded to source control.  Thus, you need an extension like Web Compiler that compile the SASS file to CSS file and minimize it.


### Error Handling


This topic will be described in more detail in the different section later.


## NuGet Packages

```

+ install-package IdentityModel

+ install-package Microsoft.AspNetCore.Authentication.OpenIdConnect
+ install-package Microsoft.AspNetCore.JsonPatch

+ install-package Microsoft.Extensions.Configuration.Json

+ install-package Microsoft.IdentityModel.Protocols.OpenIdConnect

+ install-package NWebSec.AspNetCore.Middleware

+ install-package Serilog.AspNetCore

+ install-package Serilog.Enrichers.AspnetcoreHttpcontext
+ install-package Serilog.Enrichers.Environment
+ install-package Serilog.Enrichers.Memory
+ install-package Serilog.Enrichers.Process
+ install-package Serilog.Enrichers.Thread

+ install-package Serilog.Exceptions

+ install-package Serilog.Formatting.Compact

+ install-package Serilog.Settings.Configuration

+ install-package Serilog.Sinks.Async
+ install-package Serilog.Sinks.Console
+ install-package Serilog.Sinks.Email
+ install-package Serilog.Sinks.MSSqlServer
+ install-package Serilog.Sinks.RollingFile

```
 
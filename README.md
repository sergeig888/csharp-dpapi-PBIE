# csharp-dpapi-PBIE
C# sample project for secret and credential protection using [DPAPI](https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection)

#### Why was this sample project created?

Power BI Embedded (PBIE) and API require the use of either [master identity](https://docs.microsoft.com/en-us/power-bi/developer/embed-sample-for-customers#register-an-application-in-azure-active-directory-azure-ad) or [service principal](https://docs.microsoft.com/en-us/power-bi/developer/embed-service-principal).  Most PBIE samples include code fragments that read plain text credentials. It is not a good idea to store credentials and secrets in plain text in the code or a config file even for temporary throw away lowest possible privilege service accounts. The use of DPAPI provides very strong secret protection that is very straight forward to integrate into any project that is targeting Windows.

#### How to leverage this code in your project?

The console app in this project will generate DPAPI protected 64 bit string of user supplied input string and store it in a user specified file. Your application code can decrypt that string when it is necessary to use the master identity or service principal credentials to obtain API access token. The encrypted string can be decrypted only on the machine where you generated it (or, if during the encryption step you set more restrictive CurrentUser scope, only by a specific user on the machine). This means that even if a malicious actor sees the encrypted 64 bit string in your project code or manages to exfiltrate the file that contains the encrypted string it will be useless without the access to the specific PC/sever with the ability to execute decrypt function on it with proper scope.

Here is sample code fragment that shows how to decrypt 64 bit encoded DPAPI encrypted string in .Net project:

```cs
//add this using and reference to System.Security to your project
using System.Security.Cryptography;

...
//code below assumes that user put 64bit encrypted string and code page identifier in the config file
private static readonly string Password = DecryptPwdString(ConfigurationManager.AppSettings["pbiPassword"]);
...

private static string DecryptPwdString(string protectedString64Bit)
{
    byte[] plainText = ProtectedData.Unprotect(System.Convert.FromBase64String(protectedString64Bit), null, DataProtectionScope.CurrentUser);

    Encoding codePage = Encoding.GetEncoding(Convert.ToInt32(ConfigurationManager.AppSettings["codePage"]));

    return codePage.GetString(plainText);
}
```



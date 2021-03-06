# Thinktecture.IdentityServer v2 #

[project page](http://thinktecture.github.com/Thinktecture.IdentityServer.v2/)

Thinktecture IdentityServer is a light-weight security token service built with .NET 4.5, MVC 4, Web API and WCF.

## High level features

- Multiple protocols support (WS-Trust, WS-Federation, OAuth2, HTTP GET)
- Multiple token support (SAML 1.1/2.0, JWT)
- Out of the box integration with ASP.NET membership, roles and profile
- Can be integrated with arbitrary account and attribute stores
- Support for username/password and client certificates authentication
- Support for WS-Federation metadata
- Support for WS-Trust identity delegation
- Extensibility points to customize configuration and user management handling

## Additional Support for Sitefinity CMS
[Sitefinity CMS](http://www.sitefinity.com) 5.x, 6.x integration using SWT (SWT protocol must be used for Sitefinity).
To configure, use the following steps:

1. Create a new Sitefinity project and log in and add at least one user other than the administrator. 
In order to user the backend, Sitefinity will need to match the username with one in whatever membership provider you're using.
So if you're using the default one that comes with Sitefinity, you'll need to create a user on both ends with the same name.
 Remember the user name that you added. 

2. In the SecurityConfig file of your Sitefinity application (/App_Data/Sitefinity/Configuration/SecurityConfig.config) add the following line:
```
	<add key="<Your Hex key here>" encoding="Hexadecimal" membershipProvider="Default" realm="<Your Site ID>"/>
```
	The key must be a string of hex characters and "Your Site ID" must be the unique URI of your STS/IdentityServer
you entered in the general settings area.

	
3. In the web.config file of your Sitefinity application, locate the <wsFederation>
 element & change the issuer attribute to point to your IdentityServer installation:
```
	<wsFederation passiveRedirectEnabled="true" issuer="https://<Your-IdentityServer>/issue/sitefinity" realm="http://localhost" requireHttps="false"/>
```
4. Install IdentityServer as you normally would. You can find out how to do that by watching
[this](http://vimeo.com/51088126). 

5. Enable the Sitefinity protocol under the "Protocols" section. Sitefinity is considered here as a new "protocol", even though it's more of a modification
of an existing one. 

6. Log into your IdentityServer and add a relying party if you haven't already. 
Be sure to include the port number if your relying party is on localhost. Set up things as usual
but in the Symmetric Key field add the Hex key you entered in step 1 - Don't generate one. 

7. Add a user to IdentityServer's user manager with the exact same name you used in step 1. Make
sure they are in the IdentityServerUser role. You can always turn that off later if you need to.

8. Start the relying parting application. Navigate to the Sitefinity backend and you should be redirected
to the IdentityServer portal to login. If you're not, make sure the url in the "issuer" field of
wsFederation is valid, and that you have the Sitefinity protocol turned on.

9. Enter your username and password, hit login, and voil�! You're logged into Sitefinity.
If you experience a redirect loop, it's because Sitefinity is rejecting the provided token.
Make sure that the url in the security config you entered in step one is the exact same as
the Site ID field in the General Configuration area of IdentityServer. Also make sure you
entered the Symmetric key correctly.

10. To get logging out working on the administrative side of Sitefinity, use the following url rewrite rule
in your web.config:
```
	<rewrite>
		<rules>
		   <rule name="Sitefinity STS Signout" stopProcessing="true">
			  <match url="^sitefinity/signout$" />
			  <conditions>
				 <add input="{QUERY_STRING}" pattern="sts_signout=true" negate="true" />
			  </conditions>
			  <action type="Redirect" url="/Sitefinity/Signout?sts_signout=true" appendQueryString="true" redirectType="Temporary" />
		   </rule>
		</rules>
	 </rewrite>
```
Most likely in a real world scenario you will need a new membership provider at the very
least; the above steps are just to get you going. Enjoy and let me know if you have any
issues!

*Works with version 5.4.4010.0, 6.0.4100.0, and 6.1.4300 at the moment. If there's a version
you find that doesn't work, let me know.

Check out my blog posts for more information:

http://rfavillejr.com/blog/05-16-13/sitefinity-and-identity-server

http://rfavillejr.com/blog/07-27-13/logging-out-of-identityserver-from-sitefinity
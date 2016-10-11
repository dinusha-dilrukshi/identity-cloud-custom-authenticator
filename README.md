# identity-cloud-custom-authenticator


org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticator is a local authenticator provided by default in WSO2IS. This authenticates the user with locally available credentials. This can be either username/password or even IWA (Integrated Windows Authentication). 

Authentication logic that BasicAuthenticator having is, it first check in the primary user store and then secondary user stores.


In WSO2 Cloud, we need to authenticate the user from secondary user store first, if tenant has configured any user stores and if authentication fails from secondary user store then authenticate user from default users store of Cloud (primary user store).

BasicCustomAuthenticator provided here has been implemented to authenticate the user in above mentioned order of user stores.

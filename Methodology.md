# External Pentest

1. Start by scanning target ips via nessus, and also use nmap for manual enumeration

2. Gather employee emails,usernames via opensource gathering

3. If naming convention is firstname.lastname then we can guess many unfound users through linkdn or social media.

3. Hunt for breached credentials for company if possible or available

4. All the softwares,web apps facing internet will be most probably up to date and patched so we need to rely on password attacks

5. Make notes of all types of loign portals like owa,office 365 or etc.

6. Filter the gathered emails to valid emails by using login error based techniques or something along those lines.we can also use forgot password functanilty for this purpose

7. Remember the account lockout policy and use the tries according to that. If theres no lockout policy then spray passwords openly

8. We can use common passwords like (companynameYEAR or SeasonYEAR) or append different special characters in the end if password policy is strong

9. o365 can be sprayed by using a famous tool trevorsspray on github.Research on it(we can register free aws instances and duplicate upto 10 of them,then we can use it with this tool so each requests come through different public ips to avoid lockouts.Remember to ssh once in every instance to accept the key)

10. owa can be sprayed using msf module for it.

11. If mfa is enabled we can verify mfa status by using tool MFASweep from github.

12. 












# Internal Pentest


refer to WindowsCheatSheet and linuxcheatsheet
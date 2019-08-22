# BilkentSRS_QuickLogin
- Cross Platform application for quickly logging into Bilkent Student Registry System(SRS) 
- Runs on MacOS, Windows and Linux and supports different browsers.

### How It Works ###
The user is prompted to enter their SRS ID, SRS Password, Email Address and Email Password. 
Once all the input fields are filled a browser tab is opened and the credentials are written into the login field.
The verification code is then obtained from the email inbox to log the user into SRS.

If the remember me option is selected, the credentials are encrypted and saved locally in a file called "key.key" 

**Note:** The verification code should be sent via email and not SMS.

### Setup ###
- Clone this repository
-  ``` pip3 install -r requirements.txt ``` 
- ```python3 main.py```

### To Do ### 
- Test on more devices to ensure consistency between operating systems
- The program can be set to run faster or slower depending on the machine 

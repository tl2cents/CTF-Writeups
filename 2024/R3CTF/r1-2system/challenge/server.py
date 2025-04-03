from user import *
# from secret import FLAG1
import os
FLAG1 = b"flag{test_flag1}" + os.urandom(16).hex().encode()

LOGIN_MENU = b"""[+] Nice day!
[1]. Log In [Password]
[2]. Log In [Token]
[3]. Sign Up
[4]. Exit
"""

SYSTEM_MENU = b""" 
[1]. Reset Password
[2]. Exchange keys with sb.
[3]. Get news on public channels
[4]. Get your private key & public key
[5]. Quit
"""

PublicChannels = b""
login_tag = False
USER = Users()

AliceUsername = b'AliceIsSomeBody'
BobUsername   = b'BobCanBeAnyBody'

USER.register(AliceUsername,os.urandom(166)) 

def LoginSystem(USER): 
    global login_tag 
    option = int(input(b"Now input your option: ".decode()))
    if option == 1:
        username = bytes.fromhex(input(b"Username[HEX]: ".decode()))
        password = bytes.fromhex(input(b"Password[HEX]: ".decode()))
        login_tag,msg = USER.login_by_password(username,password)
        print(msg.decode())
        if login_tag: 
            return username 

    elif option == 2:
        username = bytes.fromhex(input(b"Username[HEX]: ".decode()))
        token = bytes.fromhex(input(b"Token[HEX]: ".decode()))
        login_tag,msg = USER.login_by_token(username,token)
        print(msg.decode())
        if login_tag:
            return username 

    elif option == 3:
        username = bytes.fromhex(input(b"Username[HEX]: ".decode()))
        if username == AliceUsername or username == AliceUsername:
            print(b"You can't!")
            return
        password = bytes.fromhex(input(b"Password[HEX]: ".decode()))
        register_tag,msg = USER.register(username,password) 
        if register_tag:
            print(f"Register successfully, {username.decode()} 's token is {msg.hex()}.".encode().decode())
        else:
            print(msg.decode())

    else:
        exit()

def R1System(USERNAME): 
    global login_tag,PublicChannels
    option = int(input((b"Hello "+ USERNAME + b",do you need any services? ").decode()))
    if option == 1: 
        new_password = bytes.fromhex(input(b"New Password[HEX]: ".decode()))
        tag,msg = USER.reset_password(USERNAME,new_password)
        print(msg.decode())
    elif option == 2:
        ToUsername = bytes.fromhex(input(b"ToUsername[HEX]:".decode()))

        if ToUsername not in USER.usernames:
            print(b"ERROR".decode())
            return False
    
        PublicChannels += transfer_A2B(USER,USERNAME,ToUsername,b" My Pubclic key is: " + USER.getsb_public_key(USERNAME).hex().encode())
        PublicChannels += transfer_A2B(USER,ToUsername,USERNAME,b" My Pubclic key is: " + USER.getsb_public_key(ToUsername).hex().encode())

        ToPublickey = b2p(USER.getsb_public_key(ToUsername))
        change_key = USER.ecdhs[USERNAME].exchange_key(ToPublickey)
        print((b"Exchanged Key is: " + change_key.hex().encode() ) .decode())

    elif option == 3:
        print(PublicChannels.decode())
    
    elif option == 4:
        print((b"Your private key is:" + USER.view_private_key(USERNAME).hex().encode()) .decode())
        print((f"Your public key is:".encode() + USER.getsb_public_key(USERNAME).hex().encode()).decode())
    
    elif option == 5:
        login_tag = False

def Alice_transfer_flag_to_Bob(AliceUsername,BobUsername):
    global PublicChannels
    PublicChannels += transfer_A2B(USER,AliceUsername,BobUsername,b" Halo bob, I will give your my flag after we exchange keys.")
    PublicChannels += transfer_A2B(USER,BobUsername,AliceUsername,b" OK, I'm ready.")
    PublicChannels += transfer_A2B(USER,AliceUsername,BobUsername,b" My Pubclic key is: " + USER.getsb_public_key(AliceUsername).hex().encode())
    PublicChannels += transfer_A2B(USER,BobUsername,AliceUsername,b" My Pubclic key is: " + USER.getsb_public_key(BobUsername).hex().encode())
    PublicChannels += transfer_A2B(USER,AliceUsername,BobUsername,b" Now its my encrypted flag:")
    PublicChannels += transfer_A2B(USER,AliceUsername,BobUsername,   FLAG1 ,enc=True)
    PublicChannels += transfer_A2B(USER,BobUsername,AliceUsername,b" Wow! I know your flag now! ")

transfer_flag = False
while 1:
    if not login_tag:
        print(LOGIN_MENU.decode())
        USERNAME = LoginSystem(USER) 
    else:
        if not transfer_flag:
            USER.register(BobUsername,os.urandom(166))
            Alice_transfer_flag_to_Bob(AliceUsername,BobUsername)
            transfer_flag = True
        print(SYSTEM_MENU.decode())
        R1System(USERNAME)
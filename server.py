# python 3.7.3
# zid: z5242677
import threading
import socket
import sys
import os


# threadAuthor
# threadTitle
# threadMessageList
# threadFileList
# threadContent

# mark the Thread by it's creater
def write_Thread_owner(Title, Owner):
    with open(Title, 'w') as file:
        file.write(Owner)
        file.write("\n")
        file.close()


def write_to_file(threadTitle, threadAuthor, threadContent):
    with open(threadTitle, "w") as file:
        file.write(threadAuthor)
        file.write("\n")
        i = 1
        for line in threadContent:
            if line.type == "message":  # if this line is MSG
                file.write(str(i) + " ")
                curr_line = line.messageAuthor + ": " + line.messageContent
                file.write(curr_line)
                file.write("\n")
                i += 1
            else:  # if this line is File
                curr_line = line.fileUploader + " uploaded " + line.fileName
                file.write(curr_line)
                file.write("\n")
    return


def open_credentials(file_name):
    username_password_dict = dict()
    if os.path.isfile(file_name):  # if file exists
        with open(file_name, "r") as file:
            lines = file.readlines()
            for line in lines:
                line = line.split("\n")
                username_password = line[0].split(' ')
                if len(username_password) == 2:
                    the_username = username_password[0]
                    the_password = username_password[1]
                    username_password_dict[the_username] = User(the_username, the_password)
    return username_password_dict


# Message
# Author
# Content


# Thread: CRT, RMV, LST, RDT,
# Message: MSG, DLT, EDT,
# Upload/Download:UPD, DWN,
# XIT: one client out
# SHT: shutdown server
def CRT(thread_title, thread_author, threaddict):
    if thread_title not in threaddict:  # if Thread Title not exists
        threaddict[thread_title] = Thread(thread_title, thread_author)
        return 0
    else:  # if Thread Title already exists
        return 1


def RMV(thread_title, thread_author, threaddict):
    if thread_title in threaddict:  # Thread exist or not
        if threaddict[thread_title].threadAuthor == thread_author:
            # remove all file
            for file in threaddict[thread_title].threadFileList:
                filename = f"{thread_title}-{file.fileName}"
                os.remove(filename)
            # remove Thread
            del threaddict[thread_title]
            os.remove(thread_title)
            return 0  # success remove
        else:
            return 2  # different author, failed remove
    else:
        return 1  # Thread not exist


def LST(threaddict):
    thread_titles = threaddict.keys()
    Title_list = []
    for thread_name in thread_titles:
        Title_list.append(thread_name)
    all_Title = "\n".join(Title_list)
    return 0, all_Title


def MSG(thread_title, message, username, threaddict):
    if thread_title in threaddict:
        # if thread exists
        tmp_line = Message(username, message)  # Class Message (username, message)
        threaddict[thread_title].threadMessageList.append(tmp_line)
        threaddict[thread_title].threadContent.append(tmp_line)
        write_to_file(threaddict[thread_title].threadTitle, threaddict[thread_title].threadAuthor,
                      threaddict[thread_title].threadContent)

        return 0  # success post
    else:
        return 1


def DLT(thread_title, message_number, username, threaddict):
    if thread_title in threaddict:
        if 1 <= message_number <= len(threaddict[thread_title].threadMessageList):
            if threaddict[thread_title].threadMessageList[message_number - 1].messageAuthor == username:
                # username match
                # then delete
                # then write to file to update
                threaddict[thread_title].threadContent.remove(
                    threaddict[thread_title].threadMessageList[message_number - 1])
                threaddict[thread_title].threadMessageList.remove(
                    threaddict[thread_title].threadMessageList[message_number - 1])
                write_to_file(threaddict[thread_title].threadTitle, threaddict[thread_title].threadAuthor,
                              threaddict[thread_title].threadContent)
                return 0
            else:
                return 1
        else:
            return 2  # number out of range
    else:
        return 3


def EDT(thread_title, message_number, new_message, username, threaddict):
    if thread_title in threaddict:
        if 1 <= message_number <= len(threaddict[thread_title].threadMessageList):
            if threaddict[thread_title].threadMessageList[message_number - 1].messageAuthor == username:
                threaddict[thread_title].threadMessageList[message_number - 1].messageContent = new_message
                write_to_file(threaddict[thread_title].threadTitle, threaddict[thread_title].threadAuthor,
                              threaddict[thread_title].threadContent)
                return 0
            else:
                return 1
        else:
            return 2
    else:
        return 3


def RDT(thread_title, username, threaddict):
    if thread_title in threaddict:
        i = 1
        content_list = []
        for line in threaddict[thread_title].threadContent:
            curr_content = ""
            if line.type == "message":
                curr_content += str(i) + " "
                i += 1
                curr_content += line.messageAuthor + ": " + line.messageContent
            elif line.type == "file":
                curr_content += line.fileUploader + " uploaded " + line.fileName
            content_list.append(curr_content)
        content = "\n".join(content_list)
        return 0, content
    else:
        empty = ""
        return 1, empty  # Thread not exist


def UPD_confirm(thread_title, username, filename, threaddict):
    if thread_title in threaddict:  # Thread exist
        for file in threaddict[thread_title].threadFileList:
            if file.fileName == filename:  # file already exist
                return 1  # file not exist
        return 0
    else:
        return 2  # Thread not exist


def UPD(username, thread_title, file_name, file_data, threaddict):
    if thread_title in threaddict:
        # threaddict[thread_title] is Class Thread
        tmp_line = File(username, file_name)
        threaddict[thread_title].threadFileList.append(tmp_line)
        threaddict[thread_title].threadContent.append(tmp_line)
        write_to_file(threaddict[thread_title].threadTitle, threaddict[thread_title].threadAuthor,
                      threaddict[thread_title].threadContent)
        with open(thread_title + "-" + file_name, "wb") as file:
            file.write(file_data)
        return 0
    else:
        return 2


def DWN(username, thread_title, file_name, threaddict):
    if thread_title in threaddict:
        for file in threaddict[thread_title].threadFileList:
            if file.fileName == file_name:
                with open(thread_title + "-" + file_name, "rb") as fl:
                    return 0, fl.read()
        #  file not exists
        return 1, None
    else:
        return 2, None


# username, password, user's socket, login or not
class User:
    client = None  # the user's client/socket
    login = False  # already login or not
    username = ""
    password = ""

    def __init__(self, the_username, the_password):
        self.client = None  # initial no client
        self.login = False  # initial not login
        self.username = the_username
        self.password = the_password


# Author
# Content
class Message:
    type = "message"
    messageAuthor = ""
    messageContent = ""

    def __init__(self, the_Author, the_content):
        self.messageAuthor = the_Author
        self.messageContent = the_content


# Uploader
# fileName
class File:
    type = "file"
    fileName = ""
    fileUploader = ""

    def __init__(self, uploader, filename):
        self.fileUploader = uploader
        self.fileName = filename


class Thread:
    threadAuthor = ""
    threadTitle = ""
    threadMessageList = []  # message in Thread  "1 Yoda: Networks is awesome"
    threadFileList = []  # file in Thread  "Yoda uploaded test.exe"
    threadContent = []  # both message and file(user to write file)

    def __init__(self, the_Title, the_Author):
        self.threadAuthor = the_Author
        self.threadTitle = the_Title
        self.threadMessageList = []
        self.threadFileList = []
        self.threadContent = []
        write_Thread_owner(self.threadTitle, self.threadAuthor)  # New Thread first line is Author


class UserDict:
    userFileName = ""
    userList = dict()

    # {username : User class}
    # User class(username,password,client,login state)
    def __init__(self, file_name):  # file_name is credentials.txt
        self.userFileName = file_name
        self.userList = open_credentials(file_name)

    def userLogin(self, username, password, client):
        if username in self.userList:  # old username
            the_user = self.userList[username]
            # User class
            if the_user.login == True:  # if already login
                return 1
            else:  # if not login
                #  if correct password
                if the_user.password == password:
                    the_user.login = True
                    the_user.client = client
                    return 0  # success login
                else:  # wrong password
                    return 2
        return 3  # username not exists, create new user

    def createNewUser(self, username, password, client):
        self.userList[username] = User(username, password)
        self.userLogin(username, password, client)
        with open(self.userFileName, "a") as file:
            file.write("\n")
            the_username_password = username + ' ' + password
            file.write(the_username_password)
        return 0

    def User_Logout(self, username):
        if username in self.userList:
            the_user = self.userList[username]
            if the_user.login == True:  # if already login
                the_user.login = False  # then logout
                return 0
            else:  # if already logout
                return 1
        return 2  # username not exist

    def Single_Client_XIT(self, client):
        the_user = None
        for username in self.userList:
            # username = User class
            if self.userList[username].client == client:
                the_user = self.userList[username]
                break
        if the_user != None:
            self.User_Logout(the_user.username)


class Server:
    serverPort = 0
    serverIP = "127.0.0.1"
    serverAdminPassword = ""  # For SHT cmd
    serverSocket = None
    userManger = None
    threadDict = None  # use to save all thread(with Thread Class)
    clientPool = []  # save all client(username)
    threadPool = []  # save all thread Title
    exit = False  # initial not exit

    def __init__(self, the_Port, the_AdminPassword):
        self.exit = False
        self.serverPort = the_Port
        self.serverAdminPassword = the_AdminPassword
        try:
            self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.serverSocket.bind((self.serverIP, self.serverPort))
        except:
            exit()
        else:
            self.userManger = UserDict("credentials.txt")
            self.threadDict = dict()
            self.clientPool = []  # save all client(username)
            self.threadPool = []  # save all thread Title

    def recv_LOGIN_username_stage(self, req, res, client):
        res["id"] = "LOGIN"
        res["stage"] = 1
        username = req["username"]
        # print(self.userManger.userList.items())
        if username in self.userManger.userList:
            res["returncode"] = 0  # 0 means OK
            if self.userManger.userList[username].login:
                #  if username already login
                res["returncode"] = 2  # 2 means already login
                print(f"{username} has already logged in")
        else:  # if username not exists
            print("New user")
            res["returncode"] = 1  # 1 means new user, enter password
        return res

    def recv_LOGIN_password_stage(self, req, res, client):
        res["id"] = "LOGIN"
        res["stage"] = 2
        username = req["username"]
        if "newpassword" in req:  # create new user
            newpassword = req["newpassword"]
            self.userManger.createNewUser(username, newpassword, client)
            res["returncode"] = 0
            res["newuser"] = 1  # new user
            print(f"{username} successfully logged in")
        else:  # just login
            password = req["password"]
            return_code = self.userManger.userLogin(username, password, client)
            if return_code == 0:
                print(f"{username} successful login")
            else:
                print("Incorrect password")
            res["returncode"] = return_code
        return res

    def recv_LOGIN(self, req, res, client):  # stage 1 and stage 2
        if req["stage"] == 1:  # server receive username
            res = self.recv_LOGIN_username_stage(req, res, client)
        elif req["stage"] == 2:  # server receive password
            res = self.recv_LOGIN_password_stage(req, res, client)
        return res

    def recv_CRT(self, req, res, client):
        res["id"] = "CRT"
        res["stage"] = 1
        username = req["username"]
        thread_title = req["threadtitle"]
        return_code = CRT(thread_title, username, self.threadDict)
        res["returncode"] = return_code
        res["threadtitle"] = thread_title
        if return_code == 0:
            print(f"Thread {thread_title} created")
        else:
            print(f"Thread {thread_title} exists")
        return res

    def recv_MSG(self, req, res, client):
        res["id"] = "MSG"
        res["stage"] = 1
        username = req["username"]
        thread_title = req["threadtitle"]
        message = req["message"]
        return_code = MSG(thread_title, message, username, self.threadDict)
        res["returncode"] = return_code
        res["threadtitle"] = thread_title
        if return_code == 0:
            print(f"Message posted to {thread_title} thread")
        else:
            print(f"{thread_title} not exists")
        return res

    def recv_DLT(self, req, res, client):
        res["id"] = "DLT"
        res["stage"] = 1
        username = req["username"]
        thread_title = req["threadtitle"]
        message_number = req["messagenumber"]
        return_code = DLT(thread_title, message_number, username, self.threadDict)
        res["returncode"] = return_code
        if res["returncode"] == 0:
            print("Message has been deleted")
        elif res["returncode"] == 1:
            print("Message cannot be deleted")
        elif res["returncode"] == 2:
            print("Message number not exists")
        elif res["returncode"] == 3:
            print("Thread " + thread_title + " not exists.")
        return res

    def recv_RDT(self, req, res, client):
        res["id"] = "RDT"
        res["stage"] = 1
        username = req["username"]
        thread_title = req["threadtitle"]
        res["threadtitle"] = thread_title
        res["returncode"], res["content"] = RDT(thread_title, username, self.threadDict)
        if res["returncode"] == 0:
            if res["content"] == "":
                print("Thread " + res["threadtitle"] + " read")
            else:
                print("Thread " + res["threadtitle"] + " read")
        else:  # NOT exist
            print("Incorrect thread specified")
        return res

    def recv_LST(self, req, res, client):
        res["id"] = "LST"
        res["stage"] = 1
        username = req["username"]
        res["returncode"], res["content"] = LST(self.threadDict)
        return res

    def recv_EDT(self, req, res, client):
        res["id"] = "EDT"
        res["stage"] = 1
        username = req["username"]
        thread_title = req["threadtitle"]
        res["threadtitle"] = thread_title
        message_number = req["messagenumber"]
        new_message = req["message"]
        res["returncode"] = EDT(thread_title, message_number, new_message, username, self.threadDict)
        if res["returncode"] == 0:
            print("Message has been edited")
        elif res["returncode"] == 1:
            print("Message cannot be edited")
        elif res["returncode"] == 2:
            print("Message not exists")
        return res

    def recv_RMV(self, req, res, client):
        res["id"] = "RMV"
        res["stage"] = 1
        username = req["username"]
        thread_title = req["threadtitle"]
        res["threadtitle"] = thread_title
        res["returncode"] = RMV(thread_title, username, self.threadDict)
        if res["returncode"] == 0:
            print("Thread " + res["threadtitle"] + " removed")
        elif res["returncode"] == 1:
            print("Thread not exists")
        elif res["returncode"] == 2:  # different user
            title = res["threadtitle"]
            print(f"Thread {title} cannot be removed")
        return res

    def recv_UPD(self, req, res, client):
        res["id"] = "UPD"
        username = req["username"]
        thread_title = req["threadtitle"]
        res["threadtitle"] = thread_title
        file_name = req["filename"]
        res["filename"] = file_name
        if req["stage"] == 1:  # confirm uploaded file correct
            res["stage"] = 1
            res["returncode"] = UPD_confirm(thread_title, username, file_name, self.threadDict)
            res["threadtitle"] = req["threadtitle"]
            res["filename"] = req["filename"]
            if res["returncode"] == 1:
                print("File already exist")
            else:
                print("Thread not exist")
        elif req["stage"] == 2:  # upload file
            res["stage"] = 2
            file_data = req["filedata"]
            res["returncode"] = UPD(username, thread_title, file_name, file_data, self.threadDict)
            print(username + " uploaded file " + file_name + " to " + thread_title + " thread")
        return res

    def recv_DWN(self, req, res, client):
        res["id"] = "DWN"
        username = req["username"]
        thread_title = req["threadtitle"]
        res["threadtitle"] = thread_title
        file_name = req["filename"]
        res["filename"] = file_name
        res["returncode"], res["filedata"] = DWN(username, thread_title, file_name, self.threadDict)
        if res["returncode"] == 0:
            print(f"{file_name} downloaded from Thread {thread_title}")
        elif res["returncode"] == 1:
            print(f"{file_name} does not exist in Thread {thread_title}")
        elif res["returncode"] == 2:
            print("Thread not exist")
        return res

    def recv_XIT(self, req, res, client, isContinue):
        res["id"] = "XIT"
        username = req["username"]
        res["returncode"] = self.userManger.User_Logout(username)
        res["username"] = username
        self.clientPool.remove(client)
        isContinue = False
        if res["returncode"] == 0:
            print(f"{username} exited")
            print("Waiting for clients")
        elif res["returncode"] == 1:
            print("User already logout")
        elif res["returncode"] == 2:
            print("User not exists")
        return res, isContinue

    def recv_SHT(self, req, res, client):
        res["id"] = "SHT"
        username = req["username"]
        password = req["password"]
        if password == self.serverAdminPassword:  # Right Admin password
            all_users = self.userManger.userList.values()
            for curr_user in all_users:
                if curr_user.login == True:
                    self.userManger.User_Logout(curr_user.username)
            res["returncode"] = 0
            print("Server shutting down")
            for curr_client in self.clientPool:
                if curr_client != client:
                    curr_client.send((str(res).encode()))
            self.exit = True
        else:  # Wrong Admin password
            res["returncode"] = 1
            print("Incorrect password")  # wrong Admin Password
        return res

    def recv(self, client):
        username = ""
        isContinue = True
        while isContinue:
            try:
                orignal_req = client.recv(9999999).decode()
                req = eval(orignal_req)
                # server receive request req
            except ConnectionError:
                self.userManger.Single_Client_XIT(client)
                self.clientPool.remove(client)
                client.close()
                return
            else:
                res = dict()  # response
                CMD_Name = req["id"]
                if CMD_Name != "LOGIN":
                    print(req["username"] + " issued " + CMD_Name + " command")
                # {  id: Command Name
                #    stage:0
                #    username:XXX
                #    password:XXX
                #
                if CMD_Name == "LOGIN":  # login cmd
                    res = self.recv_LOGIN(req, res, client)
                elif CMD_Name == "CRT":
                    res = self.recv_CRT(req, res, client)
                elif CMD_Name == "MSG":
                    res = self.recv_MSG(req, res, client)
                elif CMD_Name == "DLT":
                    res = self.recv_DLT(req, res, client)
                elif CMD_Name == "RDT":
                    res = self.recv_RDT(req, res, client)
                elif CMD_Name == "LST":
                    res = self.recv_LST(req, res, client)
                elif CMD_Name == "EDT":
                    res = self.recv_EDT(req, res, client)
                elif CMD_Name == "RMV":
                    res = self.recv_RMV(req, res, client)
                elif CMD_Name == "UPD":
                    res = self.recv_UPD(req, res, client)
                elif CMD_Name == "DWN":
                    res = self.recv_DWN(req, res, client)
                elif CMD_Name == "XIT":
                    res, isContinue = self.recv_XIT(req, res, client, isContinue)
                elif CMD_Name == "SHT":
                    res = self.recv_SHT(req, res, client)
                # print(str(res))
                client.send(str(res).encode())

    def acception(self):
        self.serverSocket.listen(20)
        print("Waiting for clients")
        while True:
            client, IP = self.serverSocket.accept()
            print("Client connected")
            self.clientPool.append(client)
            # Once new client connected,append current client
            thread = threading.Thread(target=self.recv, args=(client,))
            thread.setDaemon(True)  # prevent endless thread
            thread.start()

    def start(self):
        thread = threading.Thread(target=self.acception)
        thread.setDaemon(True)
        thread.start()
        while True:
            if self.exit:  # delete all file and SHT the server
                for thread in self.threadDict.values():  # Thread class
                    os.remove(thread.threadTitle)
                    for file in thread.threadFileList:
                        os.remove(thread.threadTitle + "-" + file.fileName)
                if os.path.isfile("credentials.txt"):  # if file exists
                    os.remove("credentials.txt")
                self.serverSocket.close()
                return


if __name__ == "__main__":
    Port = int(sys.argv[1])
    admin_password = sys.argv[2]  # For SHT command
    server = Server(Port, admin_password)
    server.start()

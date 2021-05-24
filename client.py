# python 3.7.3
# zid: z5242677
import threading
import socket
import sys


def generate_cmd_list():
    CMD_list = ["LOGIN", "CRT", "MSG", "DLT", "EDT", "LST", "RDT", "UPD", "DWN", "RMV", "XIT", "SHT"]
    return CMD_list


def Format_CMD(input_str, curr_state, start0):
    commandIdList = generate_cmd_list()
    split_str = input_str.split()
    rst = []
    rst.append(split_str[0])  # cmd CRT,MSG,DLT...
    if rst[0] not in commandIdList:  # cmd not exist
        if curr_state == start0:  # input is username or password
            rst[0] = "LOGIN"
            rst += split_str
        else:
            raise Exception()
    elif rst[0] in ["MSG", "EDT"]:
        rst.append(split_str[1])
        # MSG 9331 Networks exam PWNED me
        # Networks exam PWNED me
        if rst[0] == "MSG":
            rst.append(input_str.replace("MSG " + split_str[1] + " ", ""))
        else:
            #  EDT 3331 1 I PWNED Networks exam
            #  I PWNED Networks exam
            rst.append(split_str[2])
            rst.append(input_str.replace("EDT " + split_str[1] + " " + split_str[2] + " ", ""))
    else:
        rst += split_str[1:]
    return rst


class Client:
    serverIP = ""
    serverPort = 0
    clientSocket = None

    start0 = "send username and password"  # start0
    wait0 = "wait username and password"  # wait0
    start1 = "send command"  # start1
    wait1 = "recv command"  # wait1
    exit_stage = "client exit"  # exit
    curr_state = start0  # send username/password

    username = ""  # current user
    currentStage = 1  # 1 send username/ask UPD file ,2 send password/common cmd
    returnCode = 0  # 0 correct,1,2,3
    UPD_Filename = ""  # curr file to upload
    UPD_ThreadTitle = ""  # curr Thread to CRT
    exit = False

    def __init__(self, the_IP, the_Port):
        self.serverIP = the_IP  # 127.0.0.1
        self.serverPort = the_Port
        try:
            self.clientSocket = socket.socket()
            self.clientSocket.connect((self.serverIP, self.serverPort))
        except:
            exit()

    def recv_LOGIN(self, res):  # login res
        if res["stage"] == 1:  # check username stage
            if res["returncode"] == 2:  # already login
                print(f"{self.username} has already logged in")
                self.curr_state = self.start0
            else:
                self.curr_state = self.start0
                self.currentStage = 2
        elif res["stage"] == 2:  # check password
            self.currentStage = 1  # now client can input cmd CRT,SHT...
            if res["returncode"] == 0:
                if "newuser" in res:
                    pass
                else:
                    print("Welcome to the forum")
                self.curr_state = self.start1
            elif res["returncode"] == 1:
                print(f"{self.username} has already logged in")
                self.curr_state = self.start0
            elif res["returncode"] == 2:
                print("Invalid password")
                self.curr_state = self.start0

    # response of CRT
    def recv_CRT(self, res):
        if res["returncode"] == 0:
            print("Thread " + res["threadtitle"] + " created")
        else:
            print("Thread " + res["threadtitle"] + " exists")
        self.curr_state = self.start1

    # response of MSG
    def recv_MSG(self, res):
        if res["returncode"] == 0:
            print("Message posted to " + res["threadtitle"] + " thread")
        else:
            print("Thread " + res["threadtitle"] + " not exists")
        self.curr_state = self.start1

    # response of DLT
    def recv_DLT(self, res):
        if res["returncode"] == 0:
            print("The message has been deleted")
        elif res["returncode"] == 1:  # different author
            print("The message belongs to another user and cannot be edited")
        elif res["returncode"] == 2:  # wrong MSG number
            print("Message number not exists")
        elif res["returncode"] == 3:  # No such Thread
            print("Thread not exists")
        self.curr_state = self.start1

    # response of RDT
    def recv_RDT(self, res):
        if res["returncode"] == 0:  # read success
            if res["content"] == "":
                print("Thread " + res["threadtitle"] + " is empty")
            else:
                print(res["content"])
        else:
            print("Thread " + res["threadtitle"] + " not exists")
        self.curr_state = self.start1

    # response of LST
    def recv_LST(self, res):
        if res["content"] == "":
            print("No threads to list")
        else:
            print("The list of active threads:")
            print(res["content"])
        self.curr_state = self.start1

    # response of EDT
    def recv_EDT(self, res):
        if res["returncode"] == 0:  # EDT succsee
            print("The message has been edited")
        elif res["returncode"] == 1:  # belong to different user
            print("The message belongs to another user and cannot be edited")
        elif res["returncode"] == 2:  # message not exist
            print("Message not exists")
        self.curr_state = self.start1

    # response of RMV
    def recv_RMV(self, res):
        if res["returncode"] == 0:
            Thread_title = res["threadtitle"]
            print(f"Thread {Thread_title} removed")
            # print("Thread " + res["threadtitle"] + " removed")
            # print("Thread removed")
        elif res["returncode"] == 1:  # belong to different user
            print("Thread not exists")
        elif res["returncode"] == 2:  # message not exist
            print("Thread cannot be removed")
            # print("The thread was created by another user and cannot be removed")
        self.curr_state = self.start1

    # response of UPD
    def recv_UPD(self, res):
        if self.currentStage == 1:
            if res["returncode"] == 0:  # can create this file
                self.currentStage = 2
                self.UPD_Filename = res["filename"]
                self.UPD_ThreadTitle = res["threadtitle"]
            elif res["returncode"] == 1:  # file already exist
                self.currentStage = 1
                print("File already exist")
            else:  # 2 Thread not exist
                self.currentStage = 1
                print("Thread not exist")
        elif self.currentStage == 2:  #
            self.currentStage = 1
            print(res["filename"] + " uploaded to " + res["threadtitle"] + " thread")
        self.curr_state = self.start1

    # response of DWN
    def recv_DWN(self, res):
        if res["returncode"] == 0:  # success DWN
            with open(res["filename"], "wb") as file:
                file.write(res["filedata"])
            print(res["filename"] + " successfully" + " downloaded")
        elif res["returncode"] == 1:
            # print("File not exist")
            thread_name = res["threadtitle"]
            print(f"File does not exist in Thread {thread_name}")
        elif res["returncode"] == 2:
            print("Thread " + res["threadtitle"] + " not exist")
        self.curr_state = self.start1

    # response of XIT
    def recv_XIT(self, res):
        if res["returncode"] == 0:  # success XIT
            print("Goodbye")
            self.exit = True
            self.curr_state = self.exit_stage
        elif res["returncode"] == 1:  # already logout
            print("User already logout")
            self.curr_state = self.start1
        elif res["returncode"] == 2:  # no such user
            print("User not exists")
            self.curr_state = self.start1

    # response of SHT
    def recv_SHT(self, res):
        if res["returncode"] == 0:
            self.exit = True
            self.curr_state = self.exit_stage
        else:
            print("Incorrect password")  # wrong Admin Password
            self.curr_state = self.start1

    def action_after_recv(self, res):
        #    returncode:0 means username OK,
        #               1 means new user, enter password,
        #               2 means username already login
        if res["id"] == "LOGIN":  # login cmd
            self.recv_LOGIN(res)
        # Thread CMD
        elif res["id"] == "CRT":  # create a thread
            self.recv_CRT(res)

        elif res["id"] == "LST":  # list all thread
            self.recv_LST(res)

        elif res["id"] == "RDT":  # read messgae from a thread
            self.recv_RDT(res)

        elif res["id"] == "RMV":  # remove a thread
            self.recv_RMV(res)
        # message CMD
        elif res["id"] == "MSG":  # post message to a thread
            self.recv_MSG(res)

        elif res["id"] == "DLT":  # delete message to a thread
            self.recv_DLT(res)

        elif res["id"] == "EDT":  # edit a exist message
            self.recv_EDT(res)
        # file cmd
        elif res["id"] == "UPD":  # upload a file from client to server
            self.recv_UPD(res)

        elif res["id"] == "DWN":  # download file from server
            self.recv_DWN(res)
        # XIT or SHT
        elif res["id"] == "XIT":  # current user logout
            self.recv_XIT(res)

        elif res["id"] == "SHT":  # server shut down (delete all file)
            self.recv_SHT(res)

    # receive from client
    def recv(self):
        while True:
            try:
                res_dict = self.clientSocket.recv(9999999).decode()
                res = eval(res_dict)  # recv response from server
                self.returnCode = res["returncode"]
            except ConnectionError:
                return
            except SyntaxError:  # wrong format SHT res
                res = {"id": "SHT", "returncode": 0}
                self.returnCode = res["returncode"]
                self.action_after_recv(res)
                return
            else:
                self.action_after_recv(res)

    # send username
    def send_state0_stage_one(self, request):
        the_username = input("Enter username: ")
        request["stage"] = 1
        request["username"] = the_username
        self.username = the_username
        return request

    # send password
    def send_state0_stage_two(self, request):
        request["username"] = self.username
        if self.returnCode == 0:  # username OK, not login, Enter password
            the_password = input("Enter password:")
            request["stage"] = 2
            request["password"] = the_password
        else:  # 1 new user
            the_password = input(f"Enter new password for {self.username}:")
            request["stage"] = 2
            request["newpassword"] = the_password
        return request

    # stage1:send username, stage2:send password
    def send_state0(self, req):
        req["id"] = "LOGIN"
        if self.currentStage == 1:  # send username
            req = self.send_state0_stage_one(req)
        elif self.currentStage == 2:  # send password
            req = self.send_state0_stage_two(req)
        return req

    def send_CRT(self, req, cmd, Right_command):
        if len(cmd) != 2:
            print("Incorrect syntax for CRT")
            Right_command = False
        else:
            req["id"] = "CRT"
            req["stage"] = 1
            req["threadtitle"] = cmd[1]
        return req, Right_command

    def send_MSG(self, req, cmd, Right_command):
        if len(cmd) != 3:
            print("Incorrect syntax for MSG")
            Right_command = False
        else:
            req["id"] = "MSG"
            req["stage"] = 1
            req["threadtitle"] = cmd[1]
            req["message"] = cmd[2]
        return req, Right_command

    def send_DLT(self, req, cmd, Right_command):
        if len(cmd) != 3:
            print("Incorrect syntax for DLT")
            Right_command = False
        else:
            req["id"] = "DLT"
            req["stage"] = 1
            req["threadtitle"] = cmd[1]
            req["messagenumber"] = int(cmd[2])
        return req, Right_command

    def send_EDT(self, req, cmd, Right_command):
        if len(cmd) != 4:
            print("Incorrect syntax for EDT")
            Right_command = False
        else:
            req["id"] = "EDT"
            req["stage"] = 1
            req["threadtitle"] = cmd[1]
            req["messagenumber"] = int(cmd[2])
            req["message"] = cmd[3]
        return req, Right_command

    def send_RDT(self, req, cmd, Right_command):
        if len(cmd) != 2:
            print("Incorrect syntax for RDT")
            Right_command = False
        else:
            req["id"] = "RDT"
            req["stage"] = 1
            req["threadtitle"] = cmd[1]
        return req, Right_command

    def send_LST(self, req, cmd, Right_command):
        if len(cmd) != 1:
            print("Incorrect syntax for LST")
            Right_command = False
        else:
            req["id"] = "LST"
            req["stage"] = 1
        return req, Right_command

    def send_RMV(self, req, cmd, Right_command):
        if len(cmd) != 2:
            print("Incorrect syntax for RMV")
            Right_command = False
        else:
            req["id"] = "RMV"
            req["stage"] = 1
            req["threadtitle"] = cmd[1]
        return req, Right_command

    def send_UPD(self, req, cmd, Right_command):
        if len(cmd) > 3:
            print("Incorrect syntax for UPD")
            Right_command = False
        else:
            req["id"] = "UPD"
            if self.currentStage == 1:
                req["stage"] = 1
                req["threadtitle"] = cmd[1]
                req["filename"] = cmd[2]
            else:
                req["stage"] = 2
                req["threadtitle"] = self.UPD_ThreadTitle
                req["filename"] = self.UPD_Filename
                with open(self.UPD_Filename, "rb") as file:
                    req["filedata"] = file.read()
                    file.close()
                self.UPD_Filename = ""
                self.UPD_ThreadTitle = ""
        return req, Right_command

    def send_DWN(self, req, cmd, Right_command):
        if len(cmd) != 3:
            print("Incorrect syntax for DWN")
            Right_command = False
        else:
            req["id"] = "DWN"
            req["stage"] = 1
            req["threadtitle"] = cmd[1]
            req["filename"] = cmd[2]
        return req, Right_command

    def send_XIT(self, req, cmd, Right_command):
        if len(cmd) != 1:
            print("Incorrect syntax for XIT")
            Right_command = False
        else:
            req["id"] = "XIT"
            req["stage"] = 1
        return req, Right_command

    def send_SHT(self, req, cmd, Right_command):
        if len(cmd) != 2:
            print("Incorrect syntax for SHT")
            Right_command = False
        else:
            req["id"] = "SHT"
            req["stage"] = 1
            req["password"] = cmd[1]
        return req, Right_command

    # send cmd
    def send_state1(self, req):
        Right_command = True
        req["username"] = self.username
        command = []
        if self.currentStage == 1:
            input_str = input(
                "Enter one of the following commands: CRT, MSG, DLT, EDT, LST, RDT, UPD, DWN, RMV, XIT, SHT:")
            # command = self.parseCommand(input_str)
            command = Format_CMD(input_str, self.curr_state, self.start0)
            # command = ["MSG","9331","Networks exam PWNED me"]
        else:
            if self.UPD_Filename != "":
                command.append("UPD")
        CMD_name = command[0]  # CMD_NAME:CRT ,MSG ...
        if CMD_name == "CRT":
            req, Right_command = self.send_CRT(req, command, Right_command)
        elif CMD_name == "MSG":
            req, Right_command = self.send_MSG(req, command, Right_command)
        elif CMD_name == "DLT":
            req, Right_command = self.send_DLT(req, command, Right_command)
        elif CMD_name == "EDT":
            req, Right_command = self.send_EDT(req, command, Right_command)
        elif CMD_name == "RDT":
            req, Right_command = self.send_RDT(req, command, Right_command)
        elif CMD_name == "LST":
            req, Right_command = self.send_LST(req, command, Right_command)
        elif CMD_name == "RMV":
            req, Right_command = self.send_RMV(req, command, Right_command)
        elif CMD_name == "UPD":
            req, Right_command = self.send_UPD(req, command, Right_command)
        elif CMD_name == "DWN":
            req, Right_command = self.send_DWN(req, command, Right_command)
        elif CMD_name == "XIT":
            req, Right_command = self.send_XIT(req, command, Right_command)
        elif CMD_name == "SHT":
            req, Right_command = self.send_SHT(req, command, Right_command)
        return req, Right_command

    def send(self):
        while True:
            try:
                req = dict()  # use to save segment
                # req:
                # {  id: Command Name
                #    stage:0
                #    username:XXX
                #    password:XXX
                #    newpassword:XXX
                #    stage:1 enter username, 2 enter password
                #          1 confirm file  , 2 transfer file
                #    returncode:0 means username OK,
                #               1 means new user, enter password,
                #               2 means username already login }

                if self.curr_state == self.exit_stage:  # exit
                    return
                # wait message from server
                elif self.curr_state == self.wait0 or self.curr_state == self.wait1:
                    pass
                # send message to server
                elif self.curr_state == self.start0 or self.curr_state == self.start1:
                    if self.curr_state == self.start0:
                        req = self.send_state0(req)
                        self.clientSocket.send(str(req).encode())
                        self.curr_state = self.wait0
                    else:
                        req, Right_command = self.send_state1(req)
                        if Right_command == True:
                            self.clientSocket.send(str(req).encode())
                            self.curr_state = self.wait1
                        else:
                            pass
            except Exception:
                print("Invalid command")
                continue

    def start(self):
        recv_thread = threading.Thread(target=self.recv)
        recv_thread.setDaemon(True)
        recv_thread.start()
        send_thread = threading.Thread(target=self.send)
        send_thread.setDaemon(True)
        send_thread.start()
        while True:  # check if exit or not
            if self.exit == True:
                print("Goodbye. Server shutting down")
                self.clientSocket.close()
                return


if __name__ == "__main__":
    IP = sys.argv[1]
    Port = int(sys.argv[2])
    client = Client(IP, Port)
    client.start()

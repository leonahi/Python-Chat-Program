import sys

#if not sys.hexversion > 0x03000000:
#    python_version = 2
#else:
#    python_version = 3

#if python_version == 2:
from Tkinter import *
from tkFileDialog import asksaveasfilename
#if python_version == 3:
#    from tkinter import *
#    from tkinter.filedialog import asksaveasfilename


#-----------------------------------------------------------------------------
# Contacts window

def contacts_window(master):
    """Displays the contacts window, allowing the user to select a recent
    connection to reuse.

    """
    global contact_array
    cWindow = Toplevel(master)
    cWindow.title("Contacts")
    cWindow.grab_set()
    scrollbar = Scrollbar(cWindow, orient=VERTICAL)
    listbox = Listbox(cWindow, yscrollcommand=scrollbar.set)
    scrollbar.config(command=listbox.yview)
    scrollbar.pack(side=RIGHT, fill=Y)
    buttons = Frame(cWindow)
    cBut = Button(buttons, text="Connect",
                  command=lambda: contacts_connect(
                                      listbox.get(ACTIVE).split(" ")))
    cBut.pack(side=LEFT)
    dBut = Button(buttons, text="Remove",
                  command=lambda: contacts_remove(
                                      listbox.get(ACTIVE).split(" "), listbox))
    dBut.pack(side=LEFT)
    aBut = Button(buttons, text="Add",
                  command=lambda: contacts_add(listbox, cWindow))
    aBut.pack(side=LEFT)
    buttons.pack(side=BOTTOM)

    for person in contact_array:
        listbox.insert(END, contact_array[person][1] + " " +
                       person + " " + contact_array[person][0])
    listbox.pack(side=LEFT, fill=BOTH, expand=1)

def contacts_connect(item):
    """Establish a connection between two contacts."""
    Client(item[1], int(item[2])).start()

def contacts_remove(item, listbox):
    """Remove a contact."""
    if listbox.size() != 0:
        listbox.delete(ACTIVE)
        global contact_array
        h = contact_array.pop(item[1])


def contacts_add(listbox, master):
    """Add a contact."""
    aWindow = Toplevel(master)
    aWindow.title("Contact add")
    Label(aWindow, text="Username:").grid(row=0)
    name = Entry(aWindow)
    name.focus_set()
    name.grid(row=0, column=1)
    Label(aWindow, text="IP:").grid(row=1)
    ip = Entry(aWindow)
    ip.grid(row=1, column=1)
    Label(aWindow, text="Port:").grid(row=2)
    port = Entry(aWindow)
    port.grid(row=2, column=1)
    go = Button(aWindow, text="Add", command=lambda:
                contacts_add_helper(name.get(), ip.get(), port.get(),
                                    aWindow, listbox))
    go.grid(row=3, column=1)


def contacts_add_helper(username, ip, port, window, listbox):
    """Contact adding helper function. Recognizes invalid usernames and
    adds contact to listbox and contact_array.

    """
    for letter in username:
        if letter == " " or letter == "\n":
            error_window(self.root, "Invalid username. No spaces allowed.")
            return
    if options_sanitation(port, ip):
        listbox.insert(END, username + " " + ip + " " + port)
        contact_array[ip] = [port, username]
        window.destroy()
        return


class ui_tk(object):

    def __init__(self, QuickClient, QuickServer, processUserText, toOne,
                 toTwo, connects, processFlag, processUserCommands,
                 client_options_window):

        self.root = Tk()
        self.root.title("Chat")

        self.menubar = Menu(self.root)

        file_menu = Menu(self.menubar, tearoff=0)
        file_menu.add_command(label="Save chat", command=lambda: self.saveHistory())
        file_menu.add_command(label="Change username",
                              command=lambda: self.username_options_window())
        file_menu.add_command(label="Exit", command=lambda: self.root.destroy())
        self.menubar.add_cascade(label="File", menu=file_menu)

        connection_menu = Menu(self.menubar, tearoff=0)
        connection_menu.add_command(label="Quick Connect", command=QuickClient)
        connection_menu.add_command(
            label="Connect on port", command=lambda: client_options_window(self.root))
        connection_menu.add_command(
            label="Disconnect", command=lambda: processFlag("-001"))
        self.menubar.add_cascade(label="Connect", menu=connection_menu)

        server_menu = Menu(self.menubar, tearoff=0)
        server_menu.add_command(label="Launch server", command=QuickServer)
        server_menu.add_command(label="Listen on port",
                                command=lambda: server_options_window(self.root))
        self.menubar.add_cascade(label="Server", menu=server_menu)

        self.menubar.add_command(label="Contacts", command=lambda:
                            contacts_window(self.root))

        self.root.config(menu=self.menubar)

        main_body = Frame(self.root, height=20, width=50)

        self.main_body_text = Text(main_body)
        body_text_scroll = Scrollbar(main_body)
        self.main_body_text.focus_set()
        body_text_scroll.pack(side=RIGHT, fill=Y)
        self.main_body_text.pack(side=LEFT, fill=Y)
        body_text_scroll.config(command=self.main_body_text.yview)
        self.main_body_text.config(yscrollcommand=body_text_scroll.set)
        main_body.pack()

        self.main_body_text.insert(END, "Welcome to the chat program!")
        self.main_body_text.config(state=DISABLED)

        text_input = Entry(self.root, width=60)
        text_input.bind("<Return>", processUserText)
        text_input.pack()

        statusConnect = StringVar()
        statusConnect.set("Connect")
        clientType = 1
        Radiobutton(self.root, text="Client", variable=clientType,
                    value=0, command=toOne).pack(anchor=E)
        Radiobutton(self.root, text="Server", variable=clientType,
                    value=1, command=toTwo).pack(anchor=E)
        self.connecter = Button(self.root, textvariable=statusConnect,
                           command=lambda: connects(clientType, self.root))
        self.connecter.pack()

        # XXX. dont like doing this... get over this somehow
        self.processUserCommands = processUserCommands

    #    load_contacts()

    #------------------------------------------------------------#

    def run(self):
        self.root.mainloop()

    def saveHistory(self):
        """Saves history with Tkinter's asksaveasfilename dialog."""
        file_name = asksaveasfilename(
            title="Choose save location",
            filetypes=[('Plain text', '*.txt'), ('Any File', '*.*')])
        try:
            filehandle = open(file_name + ".txt", "w")
        except IOError:
            print("Can't save history.")
            return
        contents = self.main_body_text.get(1.0, END)
        for line in contents:
            filehandle.write(line)
        filehandle.close()


    def username_options_window(self):
        """Launches username options window for setting username."""
        top = Toplevel(self.root)
        top.title("Username options")
        top.grab_set()
        Label(top, text="Username:").grid(row=0)
        name = Entry(top)
        name.focus_set()
        name.grid(row=0, column=1)
        go = Button(top, text="Change", command=lambda:
                    self.username_options_go(name.get(), top))
        go.grid(row=1, column=1)

    def username_options_go(self, name, window):
        """Processes the options entered by the user in the
        server options window.

        """
        self.processUserCommands("nick", [name])
        window.destroy()
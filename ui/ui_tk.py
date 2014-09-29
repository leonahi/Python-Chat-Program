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
            error_window(root, "Invalid username. No spaces allowed.")
            return
    if options_sanitation(port, ip):
        listbox.insert(END, username + " " + ip + " " + port)
        contact_array[ip] = [port, username]
        window.destroy()
        return


def ui_tk(QuickClient, QuickServer, processUserText, toOne, toTwo, connects):

    root = Tk()
    root.title("Chat")

    menubar = Menu(root)

    file_menu = Menu(menubar, tearoff=0)
    file_menu.add_command(label="Save chat", command=lambda: saveHistory())
    file_menu.add_command(label="Change username",
                          command=lambda: username_options_window(root))
    file_menu.add_command(label="Exit", command=lambda: root.destroy())
    menubar.add_cascade(label="File", menu=file_menu)

    connection_menu = Menu(menubar, tearoff=0)
    connection_menu.add_command(label="Quick Connect", command=QuickClient)
    connection_menu.add_command(
        label="Connect on port", command=lambda: client_options_window(root))
    connection_menu.add_command(
        label="Disconnect", command=lambda: processFlag("-001"))
    menubar.add_cascade(label="Connect", menu=connection_menu)

    server_menu = Menu(menubar, tearoff=0)
    server_menu.add_command(label="Launch server", command=QuickServer)
    server_menu.add_command(label="Listen on port",
                            command=lambda: server_options_window(root))
    menubar.add_cascade(label="Server", menu=server_menu)

    menubar.add_command(label="Contacts", command=lambda:
                        contacts_window(root))

    root.config(menu=menubar)

    main_body = Frame(root, height=20, width=50)

    main_body_text = Text(main_body)
    body_text_scroll = Scrollbar(main_body)
    main_body_text.focus_set()
    body_text_scroll.pack(side=RIGHT, fill=Y)
    main_body_text.pack(side=LEFT, fill=Y)
    body_text_scroll.config(command=main_body_text.yview)
    main_body_text.config(yscrollcommand=body_text_scroll.set)
    main_body.pack()

    main_body_text.insert(END, "Welcome to the chat program!")
    main_body_text.config(state=DISABLED)

    text_input = Entry(root, width=60)
    text_input.bind("<Return>", processUserText)
    text_input.pack()

    statusConnect = StringVar()
    statusConnect.set("Connect")
    clientType = 1
    Radiobutton(root, text="Client", variable=clientType,
                value=0, command=toOne).pack(anchor=E)
    Radiobutton(root, text="Server", variable=clientType,
                value=1, command=toTwo).pack(anchor=E)
    connecter = Button(root, textvariable=statusConnect,
                       command=lambda: connects(clientType))
    connecter.pack()

#    load_contacts()

#------------------------------------------------------------#

    root.mainloop()

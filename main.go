package main

import (
	"flag"
	"fmt"
	"log"
	"time"
	"encoding/base64"
	"strings"

	"github.com/TNK-Studio/gortal/config"
	"github.com/TNK-Studio/gortal/core/jump"
	"github.com/TNK-Studio/gortal/core/sshd"
	"github.com/TNK-Studio/gortal/utils"
	"github.com/TNK-Studio/gortal/utils/logger"
	"github.com/elfgzp/ssh"
)

var (
	// Port port
	Port *int

	hostKeyFile *string
)

func init() {
	Port = flag.Int("p", 2222, "Port")
	hostKeyFile = flag.String("hk", "~/.ssh/id_rsa", "Host key file")
}

func passwordAuth(ctx ssh.Context, pass string) bool {
	config.Conf.ReadFrom(*config.ConfPath)
	var success bool
	if (len(*config.Conf.Users)) < 1 {
		success = (pass == "newuser")
	} else {
		success = jump.VarifyUser(ctx, pass)
	}
	if !success {
		time.Sleep(time.Second * 3)
	}
	return success
}

func publickKeyAuth(ctx ssh.Context, key ssh.PublicKey) bool {
	var pub string

	config.Conf.ReadFrom(*config.ConfPath)
	username := ctx.User()
	for _, user := range *config.Conf.Users {
		if user.Username == username  {
			pub = user.PublicKey
		}
	}
	decodeBytes, _ := base64.StdEncoding.DecodeString(pub)
	allowed, _, _, _, _ := ssh.ParseAuthorizedKey(decodeBytes)

	return ssh.KeysEqual(key, allowed)
}

func sessionHandler(sess *ssh.Session) {
	defer func() {
		(*sess).Close()
	}()

	rawCmd := (*sess).RawCommand()
	cmd, args, err := sshd.ParseRawCommand(rawCmd)
	if err != nil {
		sshd.ErrorInfo(err, sess)
		return
	}

	switch cmd {
	case "scp":
		sshd.ExecuteSCP(args, sess)
	default:
		// Check if this is a direct login command (server:sshUser format)
		// First check if the command itself is a direct login format
		if cmd != "" && strings.Contains(cmd, ":") {
			// The command itself might be server:sshUser format
			if directLoginHandler(sess, []string{cmd}) {
				return
			}
		}
		// Then check if any argument is a direct login format
		if len(args) > 0 {
			// Try to parse direct login format
			if directLoginHandler(sess, args) {
				return
			}
		}
		// If no direct login command found, check if we should show help
		if cmd == "help" || cmd == "-h" || cmd == "--help" {
			showDirectLoginHelp(sess)
			return
		}
		sshHandler(sess)
	}
}

func sshHandler(sess *ssh.Session) {
	jps := jump.Service{}
	jps.Run(sess)
}

// showDirectLoginHelp shows help information for direct login
func showDirectLoginHelp(sess *ssh.Session) {
	helpMsg := `
Direct Login Help:
==================

Format: server:sshUser

Examples:
  - production-server:root
  - staging-server:ubuntu
  - web-server:deploy

To see available servers and SSH users, use the interactive menu.
To use direct login, specify the server name and SSH user name separated by colon.

Note: You must have permission to access the specified server and SSH user.
`
	sshd.Info(helpMsg, sess)
}

func scpHandler(args []string, sess *ssh.Session) {
	sshd.ExecuteSCP(args, sess)
}

// directLoginHandler handles direct login commands in format: server:sshUser
// Returns true if it was a direct login command, false otherwise
func directLoginHandler(sess *ssh.Session, args []string) bool {
	// Check if the first argument matches server:sshUser format
	if len(args) < 1 {
		return false
	}

	arg := args[0]
	
	// Check for help command
	if arg == "help" || arg == "-h" || arg == "--help" {
		showDirectLoginHelp(sess)
		return true
	}
	
	// Check if it contains colon (server:sshUser format)
	if !strings.Contains(arg, ":") {
		return false
	}

	parts := strings.SplitN(arg, ":", 2)
	if len(parts) != 2 {
		return false
	}

	serverName := strings.TrimSpace(parts[0])
	sshUserName := strings.TrimSpace(parts[1])
	
	// Validate that both parts are non-empty
	if serverName == "" || sshUserName == "" {
		return false
	}

	// Read config
	config.Conf.ReadFrom(*config.ConfPath)

	// Get current user
	currentUser := (*sess).User()
	user := config.Conf.GetUserByUsername(currentUser)
	if user == nil {
		sshd.ErrorInfo(fmt.Errorf("User '%s' not found in configuration", currentUser), sess)
		return true
	}

	// Find server by name
	server := config.Conf.GetServerByName(serverName)
	if server == nil {
		sshd.ErrorInfo(fmt.Errorf("Server '%s' not found. Available servers: %v", serverName, getAvailableServerNames()), sess)
		return true
	}

	// Check if user has access to this server
	userServers := config.Conf.GetUserServers(user)
	serverKey := ""
	for key, s := range userServers {
		if s == server {
			serverKey = key
			break
		}
	}
	if serverKey == "" {
		sshd.ErrorInfo(fmt.Errorf("User '%s' does not have access to server '%s'", currentUser, serverName), sess)
		return true
	}

	// Find SSH user for this server
	sshUsers := config.Conf.GetServerSSHUsers(user, server)
	var sshUser *config.SSHUser
	var sshUserKey string
	for key, su := range sshUsers {
		if su.SSHUsername == sshUserName {
			sshUser = su
			sshUserKey = key
			break
		}
	}
	if sshUser == nil {
		availableUsers := make([]string, 0)
		for _, su := range sshUsers {
			availableUsers = append(availableUsers, su.SSHUsername)
		}
		sshd.ErrorInfo(fmt.Errorf("SSH user '%s' not found for server '%s'. Available users: %v", sshUserName, serverName, availableUsers), sess)
		return true
	}

	// Validate identity file exists
	if !utils.FileExited(sshUser.IdentityFile) {
		sshd.ErrorInfo(fmt.Errorf("Identity file '%s' not found for SSH user '%s'", sshUser.IdentityFile, sshUserName), sess)
		return true
	}

	// Log direct login attempt
	logger.Logger.Infof("Direct login: user '%s' -> server '%s' (key: %s) -> SSH user '%s' (key: %s)", 
		currentUser, serverName, serverKey, sshUserName, sshUserKey)

	// Check if the session has a PTY
	_, _, isPty := (*sess).Pty()
	if !isPty {
		sshd.ErrorInfo(fmt.Errorf("Direct login requires a PTY. Please use an interactive SSH session."), sess)
		return true
	}

	// Establish direct SSH connection
	err := sshd.NewTerminal(server, sshUser, sess)
	if err != nil {
		sshd.ErrorInfo(fmt.Errorf("Failed to connect to target server: %v", err), sess)
		return true
	}

	return true
}

// getAvailableServerNames returns list of available server names for error messages
func getAvailableServerNames() []string {
	names := make([]string, 0)
	if config.Conf.Servers == nil {
		return names
	}
	for _, server := range *config.Conf.Servers {
		names = append(names, server.Name)
	}
	return names
}

func main() {
	flag.Parse()

	if !utils.FileExited(*hostKeyFile) {
		sshd.GenKey(*hostKeyFile)
	}

	ssh.Handle(func(sess ssh.Session) {
		defer func() {
			if e, ok := recover().(error); ok {
				logger.Logger.Panic(e)
			}
		}()
		sessionHandler(&sess)
	})

	log.Printf("starting ssh server on port %d...\n", *Port)
	log.Fatal(ssh.ListenAndServe(
		fmt.Sprintf(":%d", *Port),
		nil,
		ssh.PasswordAuth(passwordAuth),
		ssh.PublicKeyAuth(publickKeyAuth),
		ssh.HostKeyFile(utils.FilePath(*hostKeyFile)),
	),
	)
}

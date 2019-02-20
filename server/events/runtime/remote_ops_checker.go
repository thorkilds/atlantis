package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/go-tfe"
	"github.com/hashicorp/hcl"
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"github.com/runatlantis/atlantis/server/logging"
	"io/ioutil"
	"os"
	"path/filepath"
)

type RemoteOpsChecker interface {
	UsingRemoteOps(log *logging.SimpleLogger, workspace string, projectAbsPath string) (bool, error)
}

type DefaultRemoteOpsChecker struct {
}

func (d *DefaultRemoteOpsChecker) UsingRemoteOps(log *logging.SimpleLogger, workspace string, projectAbsPath string) (bool, error) {
	log.Debug("reading statefile to check if using TFE remote ops")

	// First, parse the statefile to determine the backend type.
	stateBytes, err := ioutil.ReadFile(filepath.Join(projectAbsPath, ".terraform/terraform.tfstate"))
	if err != nil {
		if os.IsNotExist(err) {
			log.Warn("statefile does not exist, assuming not using remote ops")
			return false, nil
		}
		return false, err
	}

	type Statefile struct {
		Backend *struct {
			Type   *string `json:"type,omitempty"`
			Config *struct {
				Hostname     *string `json:"hostname,omitempty"`
				Organization *string `json:"organization,omitempty"`
				Workspaces   *[]struct {
					Name   string `json:"name"`
					Prefix string `json:"prefix"`
				} `json:"workspaces,omitempty"`
			} `json:"config,omitempty"`
		} `json:"backend,omitempty"`
	}

	var statefile Statefile
	err = json.Unmarshal(stateBytes, &statefile)
	if err != nil {
		return false, err
	}

	type RemoteBackend struct {
		Hostname        string
		Organization    string
		WorkspaceName   string
		WorkspacePrefix string
	}

	// Validate the statefile.
	isRemote, backend, err := (func(s Statefile) (bool, RemoteBackend, error) {
		backend := statefile.Backend
		if backend == nil {
			log.Debug("statefile had no backend block so remote ops are not being used")
			return false, RemoteBackend{}, nil
		}

		if *backend.Type != "remote" {
			log.Debug("statefile backend type is %q, not \"remote\" so remote ops are not being used", *statefile.Backend.Type)
			return false, RemoteBackend{}, nil
		}

		if backend.Config == nil {
			return false, RemoteBackend{}, errors.New("statefile backend is of type \"remote\" but has no backend.config block")
		}

		if backend.Config.Organization == nil {
			return false, RemoteBackend{}, errors.New("statefile backend is of type \"remote\" but has no organization set")
		}
		org := *backend.Config.Organization

		if backend.Config.Workspaces == nil || len(*backend.Config.Workspaces) == 0 {
			return false, RemoteBackend{}, errors.New("statefile backend is of type \"remote\" but has no workspaces set")
		}
		workspace := (*backend.Config.Workspaces)[0]
		if workspace.Name == "" && workspace.Prefix == "" {
			return false, RemoteBackend{}, errors.New("statefile backend is of type \"remote\" but workspace has neither name nor prefix set")
		}

		hostname := "app.terraform.io"
		if backend.Config.Hostname != nil {
			hostname = *backend.Config.Hostname
		}
		return true, RemoteBackend{
			Hostname:        hostname,
			Organization:    org,
			WorkspaceName:   workspace.Name,
			WorkspacePrefix: workspace.Prefix,
		}, nil
	})(statefile)

	if err != nil {
		return false, err
	}
	if !isRemote {
		log.Debug("determined not using remote backend")
		return false, nil
	}

	log.Debug("determined using remote backend with hostname: %q, org: %q, workspace name: %q, workspace prefix: %q",
		backend.Hostname, backend.Organization, backend.WorkspaceName, backend.WorkspacePrefix)

	// Read and parse the ~/.terraformrc file.
	log.Debug("retrieving TFE token from .terraformrc file")
	home, err := homedir.Dir()
	if err != nil {
		return false, errors.Wrap(err, "retrieving token from .terraformrc file")
	}
	rcFilePath := filepath.Join(home, ".terraformrc")
	rcFileBytes, err := ioutil.ReadFile(rcFilePath)
	if err != nil {
		return false, errors.Wrap(err, "retrieving token from .terraformrc file")
	}
	obj, err := hcl.Parse(string(rcFileBytes))
	if err != nil {
		return false, errors.Wrap(err, "parsing .terraformrc file to retrieve TFE token")
	}

	type Config struct {
		Credentials map[string]map[string]interface{} `hcl:"credentials"`
	}
	var rcFile Config
	if err := hcl.DecodeObject(&rcFile, obj); err != nil {
		return false, errors.Wrap(err, "decoding .terraformrc file to retrieve TFE token")
	}

	hostnameConf, ok := rcFile.Credentials[backend.Hostname]
	if !ok {
		return false, fmt.Errorf("found no credentials config for hostname %q in %q", backend.Hostname, rcFilePath)
	}
	tokenGeneric, ok := hostnameConf["token"]
	if !ok {
		return false, fmt.Errorf("found no token key in config for hostname %q in %q", backend.Hostname, rcFilePath)
	}
	token := tokenGeneric.(string)
	log.Debug("successfully found token for hostname %q", backend.Hostname)

	// Now that we've got our token, we can make the TFE API call to figure out
	// if this org uses the remote backend.
	log.Debug("calling TFE API to determine entitlements")
	client, err := tfe.NewClient(&tfe.Config{Token: token})
	if err != nil {
		return false, errors.Wrap(err, "creating TFE API client to determine if using remote ops")
	}
	entitlements, err := client.Organizations.Entitlements(context.Background(), backend.Organization)
	if err != nil {
		return false, errors.Wrap(err, "calling TFE API to determine if using remote ops")
	}
	if entitlements == nil {
		return false, errors.New("got nil entitlements calling TFE API to determine if using remote ops")
	}
	if !entitlements.Operations {
		log.Debug("organization %q does not have the operations entitlement so remote ops are not being used", backend.Organization)
		return false, nil
	}

	// If they're entitled to use remote ops, we check if this workspace
	// is using remote ops.
	tfeWorkspaceName := backend.WorkspaceName
	if backend.WorkspacePrefix != "" {
		tfeWorkspaceName = backend.WorkspacePrefix + workspace
	}
	log.Debug("organization %q has the operations entitlement. Now checking if workspace %q has remote ops enabled", backend.Organization, tfeWorkspaceName)
	tfeWorkspace, err := client.Workspaces.Read(context.Background(), backend.Organization, tfeWorkspaceName)
	if err != nil {
		return false, errors.Wrap(err, "calling TFE API to determine if using remote ops")
	}
	if tfeWorkspace == nil {
		return false, errors.New("got nil workspace calling TFE API to determine if using remote ops")
	}
	log.Debug("workspace %q has remote ops set to %t", tfeWorkspaceName, tfeWorkspace.Operations)
	return tfeWorkspace.Operations, nil
}

/*
Copyright The ORAS Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"fmt"
	"io/fs"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/containerd/containerd/remotes"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/pkg/auth"
	"oras.land/oras-go/pkg/auth/docker"
	"oras.land/oras-go/pkg/content"
	"oras.land/oras-go/pkg/oras"
)

const (
	falcoRuleConfigMediaType   = "application/vnd.cncf.falco.rule.config.v1+yaml"
	falcoRuleLayerMediaType    = "application/vnd.cncf.falco.rule.layer.v1+yaml"
	falcoPluginConfigMediaType = "application/vnd.cncf.falco.plugin.config.v1+yaml"
	falcoPluginLayerMediaType  = "application/vnd.cncf.falco.plugin.layer.v1+yaml"
	hostname                   = "ghcr.io"
	user                       = "loresuso"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

type ArtifactType int64

const (
	Rule ArtifactType = iota
	Plugin
)

type Client struct {
	context    context.Context
	authorizer auth.Client
	resolver   remotes.Resolver
}

func NewClient() (*Client, error) {
	c := &Client{}

	c.context = context.Background()

	authClient, err := docker.NewClientWithDockerFallback()
	if err != nil {
		return nil, err
	}
	c.authorizer = authClient

	headers := http.Header{}
	headers.Set("User-Agent", "oras")
	opts := []auth.ResolverOption{auth.WithResolverHeaders(headers)}
	resolver, err := c.authorizer.ResolverWithOpts(opts...)
	if err != nil {
		return nil, err
	}
	c.resolver = resolver

	return c, nil
}

func (c *Client) Login() error {
	ghcrToken := os.Getenv("GHCR_TOKEN")
	if ghcrToken == "" {
		return fmt.Errorf("Cannot login: please set the GHCR_TOKEN env variable")
	}

	loginOptions := []auth.LoginOption{
		auth.WithLoginContext(c.context),
		auth.WithLoginHostname(hostname),
		auth.WithLoginUsername(user),
		auth.WithLoginSecret(ghcrToken),
	}
	err := c.authorizer.LoginWithOpts(
		loginOptions...,
	)

	return err
}

func (c *Client) Logout() error {
	return c.authorizer.Logout(c.context, hostname)
}

func (c *Client) Push(artifactType ArtifactType, data []byte, ref string, filename string) error {
	var configMediaType string
	var layerMediaType string

	if artifactType == Rule {
		configMediaType = falcoRuleConfigMediaType
		layerMediaType = falcoRuleLayerMediaType
	} else {
		configMediaType = falcoPluginConfigMediaType
		layerMediaType = falcoPluginLayerMediaType
	}

	memoryStore := content.NewMemory()
	desc, err := memoryStore.Add(filename, layerMediaType, data)
	if err != nil {
		return err
	}

	// create config
	configDesc, err := memoryStore.Add("", configMediaType, []byte(""))
	if err != nil {
		return err
	}
	memoryStore.Set(configDesc, []byte(""))

	// create manifest
	manifest, manifestDesc, err := content.GenerateManifest(&configDesc, nil, desc)
	if err != nil {
		return err
	}
	err = memoryStore.StoreManifest(ref, manifestDesc, manifest)
	if err != nil {
		return err
	}

	// fmt.Printf("Generated manifest for push: \n%s\n", string(manifest))

	registry := content.Registry{Resolver: c.resolver}

	// fmt.Printf("Pushing %s to %s...\n", data, ref)

	desc, err = oras.Copy(c.context, memoryStore, ref, registry, "")
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) Pull(artifactType ArtifactType, ref string) error {
	var configMediaType string
	var layerMediaType string

	if artifactType == Rule {
		configMediaType = falcoRuleConfigMediaType
		layerMediaType = falcoRuleLayerMediaType
	} else {
		configMediaType = falcoPluginConfigMediaType
		layerMediaType = falcoPluginLayerMediaType
	}

	registry := content.Registry{Resolver: c.resolver}
	fileStore := content.NewFile("")
	defer fileStore.Close()
	allowedMediaTypes := []string{configMediaType, layerMediaType}

	var layers []v1.Descriptor
	var rootManifest []byte

	_, err := oras.Copy(c.context, registry, ref, fileStore, "",
		oras.WithAllowedMediaTypes(allowedMediaTypes),
		oras.WithLayerDescriptors(func(descriptors []v1.Descriptor) { layers = descriptors }),
		oras.WithRootManifest(func(b []byte) { rootManifest = b }))
	if err != nil {
		return err
	}

	fmt.Println(string(rootManifest))
	fmt.Printf("%+v\n", layers)

	return nil
}

func main() {
	repo := "testrepo"
	tag := "3.0"
	ref := fmt.Sprintf("%s/%s/%s:%s", hostname, user, repo, tag)
	// fileName indicates how it will be saved once pulled
	// (keep them different for now just to see that the file is actually downloaded)
	fileName := "rule.tar.gz"

	// read content of some file you want to upload
	// let's upload some rules
	file, _ := os.OpenFile("cloudtrail-rules-0.5.0.tar.gz", 0, fs.FileMode(os.O_RDONLY))
	fileContent, _ := ioutil.ReadAll(file)

	// create a new client and login (it set an entry in /home/username/.docker/config.json)
	client, err := NewClient()
	check(err)

	err = client.Login()
	check(err)

	err = client.Push(Rule, fileContent, ref, fileName)
	check(err)

	// Pull file(s) from registry and save to disk
	err = client.Pull(Rule, ref)
	check(err)

	client.Logout()

}

/*
Copyright 2018 Google LLC

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

// Code generated by client-gen. DO NOT EDIT.

package v1beta1

import (
	"context"

	v1beta1 "github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	scheme "github.com/grafeas/kritis/pkg/kritis/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// AttestationAuthoritiesGetter has a method to return a AttestationAuthorityInterface.
// A group's client should implement this interface.
type AttestationAuthoritiesGetter interface {
	AttestationAuthorities(namespace string) AttestationAuthorityInterface
}

// AttestationAuthorityInterface has methods to work with AttestationAuthority resources.
type AttestationAuthorityInterface interface {
	Create(*v1beta1.AttestationAuthority) (*v1beta1.AttestationAuthority, error)
	Update(*v1beta1.AttestationAuthority) (*v1beta1.AttestationAuthority, error)
	Delete(name string, options *v1.DeleteOptions) error
	DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error
	Get(name string, options v1.GetOptions) (*v1beta1.AttestationAuthority, error)
	List(opts v1.ListOptions) (*v1beta1.AttestationAuthorityList, error)
	Watch(opts v1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1beta1.AttestationAuthority, err error)
	AttestationAuthorityExpansion
}

// attestationAuthorities implements AttestationAuthorityInterface
type attestationAuthorities struct {
	client rest.Interface
	ns     string
}

// newAttestationAuthorities returns a AttestationAuthorities
func newAttestationAuthorities(c *KritisV1beta1Client, namespace string) *attestationAuthorities {
	return &attestationAuthorities{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the attestationAuthority, and returns the corresponding attestationAuthority object, and an error if there is any.
func (c *attestationAuthorities) Get(name string, options v1.GetOptions) (result *v1beta1.AttestationAuthority, err error) {
	result = &v1beta1.AttestationAuthority{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("attestationauthorities").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(context.Background()).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of AttestationAuthorities that match those selectors.
func (c *attestationAuthorities) List(opts v1.ListOptions) (result *v1beta1.AttestationAuthorityList, err error) {
	result = &v1beta1.AttestationAuthorityList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("attestationauthorities").
		VersionedParams(&opts, scheme.ParameterCodec).
		Do(context.Background()).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested attestationAuthorities.
func (c *attestationAuthorities) Watch(opts v1.ListOptions) (watch.Interface, error) {
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("attestationauthorities").
		VersionedParams(&opts, scheme.ParameterCodec).
		Watch(context.Background())
}

// Create takes the representation of a attestationAuthority and creates it.  Returns the server's representation of the attestationAuthority, and an error, if there is any.
func (c *attestationAuthorities) Create(attestationAuthority *v1beta1.AttestationAuthority) (result *v1beta1.AttestationAuthority, err error) {
	result = &v1beta1.AttestationAuthority{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("attestationauthorities").
		Body(attestationAuthority).
		Do(context.Background()).
		Into(result)
	return
}

// Update takes the representation of a attestationAuthority and updates it. Returns the server's representation of the attestationAuthority, and an error, if there is any.
func (c *attestationAuthorities) Update(attestationAuthority *v1beta1.AttestationAuthority) (result *v1beta1.AttestationAuthority, err error) {
	result = &v1beta1.AttestationAuthority{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("attestationauthorities").
		Name(attestationAuthority.Name).
		Body(attestationAuthority).
		Do(context.Background()).
		Into(result)
	return
}

// Delete takes name of the attestationAuthority and deletes it. Returns an error if one occurs.
func (c *attestationAuthorities) Delete(name string, options *v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("attestationauthorities").
		Name(name).
		Body(options).
		Do(context.Background()).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *attestationAuthorities) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("attestationauthorities").
		VersionedParams(&listOptions, scheme.ParameterCodec).
		Body(options).
		Do(context.Background()).
		Error()
}

// Patch applies the patch and returns the patched attestationAuthority.
func (c *attestationAuthorities) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1beta1.AttestationAuthority, err error) {
	result = &v1beta1.AttestationAuthority{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("attestationauthorities").
		SubResource(subresources...).
		Name(name).
		Body(data).
		Do(context.Background()).
		Into(result)
	return
}

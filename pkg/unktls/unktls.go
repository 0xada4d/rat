// Code generated by go-bindata. (@generated) DO NOT EDIT.

// Package main generated by go-bindata.// sources:
// data/x509/openssl.sh
// data/x509/server.crt
// data/x509/server.key
package unktls

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

// Name return file name
func (fi bindataFileInfo) Name() string {
	return fi.name
}

// Size return file size
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}

// Mode return file mode
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}

// ModTime return file modify time
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}

// IsDir return file whether a directory
func (fi bindataFileInfo) IsDir() bool {
	return fi.mode&os.ModeDir != 0
}

// Sys return file is sys mode
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _dataX509OpensslSh = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x4c\xca\x4d\x0e\x83\x20\x10\x05\xe0\x3d\xa7\x78\x17\x98\x86\xb4\xa5\xa9\xde\x86\xc8\x5b\x61\x40\x67\xf0\x87\xdb\x1b\x77\xae\xbf\xaf\x2e\x2c\x66\x33\x94\x2b\xa4\xf0\xc8\xec\x50\x8b\xe3\xdb\x7f\xff\x90\x52\x13\x0d\x92\xd9\xeb\xd6\x60\xd4\x9d\xfa\xba\x8b\x9c\xc1\x0f\x90\x14\xbb\xe1\xf3\x0b\x90\x87\x4f\xda\x9c\xbb\x02\x00\x00\xff\xff\x37\x80\x89\xd2\x58\x00\x00\x00")

func dataX509OpensslShBytes() ([]byte, error) {
	return bindataRead(
		_dataX509OpensslSh,
		"data/x509/openssl.sh",
	)
}

func dataX509OpensslSh() (*asset, error) {
	bytes, err := dataX509OpensslShBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "data/x509/openssl.sh", size: 88, mode: os.FileMode(436), modTime: time.Unix(1599845094, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _dataX509ServerCrt = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x8c\x94\xcb\xae\xab\x36\x18\x85\xe7\x3c\x45\xe7\x51\xc5\x2d\x09\x30\xe8\xc0\x06\x07\x0c\x18\x70\x20\xdc\x66\x84\x04\x42\x80\xdc\x48\x30\xf0\xf4\xd5\xde\xaa\xda\xaa\xa7\x3a\x3a\x1e\x7e\xff\x92\xf5\x49\x4b\x5a\xbf\x7f\x3d\x88\x4c\xec\xfd\xa6\xa3\x7d\x84\x77\x58\x07\x11\xfa\xa6\x1c\xc1\xd8\xb8\x44\xba\x0e\x7a\xa9\x06\x0c\x43\x50\x63\x1b\x04\x81\x95\xd5\x99\x02\x07\x39\x23\x40\x30\xf5\xf0\x69\x86\xf8\x28\x1b\x14\x41\x9d\x1d\x00\xd9\xb5\x93\xbe\x00\x1b\xd6\x5e\xcc\x41\x90\x45\xa0\xdd\xc5\x64\x4f\x18\xa2\x99\x11\x53\x8a\x0d\xf0\x88\x8e\x92\xd8\xb9\xb1\x27\x64\xe9\xbe\x23\x21\x62\x16\xfb\xbe\x39\x06\xbc\xd8\xc7\xdb\xbe\x2b\xfb\x4d\x77\xd2\x61\xca\x15\xc9\xfe\x56\xa4\xfb\x05\xef\xa0\x70\x0e\x21\x39\x99\x74\x42\x57\x40\xbf\x7e\x87\x80\x10\x3d\x99\xc6\x4c\xda\x0d\x85\xa9\x2d\x27\x03\x9c\x77\x4c\x98\x89\x01\xd6\xe4\x5a\x32\x62\x10\x99\x23\x11\x2c\xbe\x61\xf4\x0f\xfc\x62\xff\xd6\xfc\x99\x25\xf7\x2b\x9a\x3f\xb3\xe4\x7e\xd4\xd4\x75\x10\x62\x66\xd0\xcc\x76\xee\x39\xbe\x8c\xa5\x07\x28\x82\x90\x02\xa3\xae\x51\x00\xbe\xee\xf4\xae\xd7\x35\x82\xc0\x87\x16\xe7\x5b\xdb\x38\xdf\x3b\xeb\xe6\x14\xaa\xf9\xb8\x5c\xd4\x5e\x53\xaf\x5a\x98\x7b\xfa\xde\x80\x8c\x48\x6d\xba\x1e\xa2\x4f\x19\x59\xd5\xf0\x89\xa2\x58\x75\x9b\x60\xd5\xbe\x26\x58\x25\xdd\x2d\xd9\xf0\x1e\x87\xa6\x5b\xa8\x75\x9b\xb7\xb7\x55\x1f\x55\x15\x49\x76\x2a\xb6\xaf\x6b\x91\x07\xca\xe5\xe1\xc7\x9b\xf2\x68\xbc\xe5\x3b\x5d\x1c\x87\x5d\xe6\xd2\xd7\xe2\x17\x15\xa7\x44\x3d\x3a\x86\x98\x37\xf7\xb6\xe6\x39\x6c\xf1\xca\xb8\xc9\x27\xc8\xeb\x2f\x94\xb9\x69\x72\x32\xa5\x37\x59\x25\xd7\x1a\x1b\x0f\xb5\x55\x8a\x70\xbb\xf0\x54\xb8\xb5\x03\x19\xa6\xa6\x71\xa4\x3c\x23\xef\xae\x2d\x93\xe4\xfc\xe1\x85\x12\x70\x71\xd0\x28\xa2\x91\xcd\x09\x88\xca\x24\xb4\x5d\xe8\xed\x96\x2c\x0a\xea\xb1\xb5\x1d\x51\x2c\xf2\xa7\x4b\x56\x47\x7b\x7b\xc0\x09\x82\x30\x65\x64\x88\x9e\xf4\xa6\x90\x3e\x57\xa8\x72\xde\xce\x2d\x77\x46\xb9\xd6\x5c\x18\x7d\x7c\x5e\x5d\x16\x08\x9d\xff\x98\x33\xc9\x3b\x2f\x7e\x95\xb9\x75\xac\x99\x52\xec\x96\x51\xfe\x86\xaa\xb3\x6d\xdb\xaa\xe9\x0f\x1f\xc0\x5b\x83\x18\x7a\xed\xc1\x77\x2b\x2f\xe1\x1a\x33\x29\xf6\x6b\xc7\xef\x66\xab\x8e\x97\xb8\x4c\x72\x55\x07\x0c\x01\x50\x78\x94\xa0\x35\xb3\xbe\x7a\xdf\x0b\x3e\x84\x19\xda\x21\x7c\xb1\x99\x92\x2e\xaf\x85\x44\x8f\x72\xcd\xe3\xce\xe3\x1c\x89\xd2\xfa\x93\x3c\x09\x54\x4d\x20\x1e\x4e\x98\xd1\x8c\xc0\x02\xfc\x5f\xf8\xef\x2c\x60\xdf\x59\xc4\xe8\x8e\x23\x80\x40\x50\xa9\xff\xed\xdd\xfd\xab\x77\x08\x2c\xca\x28\x0e\x2a\x66\xe2\x36\x37\x0e\x95\x73\xb0\x33\xed\xea\xcd\x2b\x98\x7e\xb6\xc5\x74\xe5\x06\x61\xd5\x84\xb7\x09\xaa\x4f\xa4\x5e\xa6\xe0\x7c\x54\x2d\xc7\x75\xab\x8b\x28\xf3\xaa\xe4\x81\x34\x0b\xbd\xb8\x22\xd1\xf9\x4d\x5d\x31\x33\xad\x68\x99\x19\xab\x1c\xba\x2e\x53\xe7\x19\x4a\x32\xe4\x36\x71\xfa\xf1\xf9\xba\xeb\xbb\x18\x8c\x7c\x53\x04\x1a\x14\xe7\x90\x2f\x03\x45\x31\x03\xad\x5a\x4d\xc7\xfc\x59\xc9\xd9\x6b\x83\xed\xd4\xdf\x6e\x1a\x77\x9d\x0c\xe1\xe3\x28\x8f\x06\x7f\x79\x99\x9d\xc3\x51\x6d\x3e\x62\x41\x54\x9d\xb9\x36\x36\x8c\x2d\xf2\x41\x9f\x6f\x91\x32\x28\xc2\x18\x3e\xef\x44\x4c\xea\xed\xc9\x6d\x8a\xa3\x4e\x9b\x83\x2c\x38\xcf\xf3\x38\xf6\x38\x96\xe3\x2d\x6c\x19\x48\x61\xcc\x21\x6d\x97\x3f\x0b\xf1\x66\x9e\xfa\xb0\x1b\x3b\x25\x75\xc6\x75\xea\x91\x7b\x9c\x37\x45\xfc\x7a\x0f\xa4\x17\x0d\xfa\x62\xed\xac\x44\x58\x3c\xc9\x22\x21\xab\xe7\x18\xdf\x27\x6c\xc3\x95\x7b\xda\xf2\x9c\xf2\x48\x6f\x44\xed\xaf\xb3\x39\x33\x5a\xdb\x66\x74\x10\xae\x23\xb5\x18\x0c\x91\x85\x61\x7f\xfe\x14\xfe\x26\x93\xee\x3d\x5f\xf2\x7e\x2c\x75\xa5\xea\x65\xcb\xe6\x84\xfe\xe0\xbe\x07\x0d\x79\xc6\x8f\x23\xf7\x67\x00\x00\x00\xff\xff\xfb\xef\xfc\x4e\x01\x05\x00\x00")

func dataX509ServerCrtBytes() ([]byte, error) {
	return bindataRead(
		_dataX509ServerCrt,
		"data/x509/server.crt",
	)
}

func dataX509ServerCrt() (*asset, error) {
	bytes, err := dataX509ServerCrtBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "data/x509/server.crt", size: 1281, mode: os.FileMode(436), modTime: time.Unix(1599845094, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _dataX509ServerKey = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x64\x95\xb7\x12\xb3\xe6\x02\x05\x7b\x9e\xc2\x3d\x73\x87\x2c\xa0\x70\xf1\x91\x73\x4e\xa2\x43\xe4\x9c\x44\x10\x4f\x7f\xc7\xbf\x4b\x9f\xf2\x54\x3b\xdb\xec\xff\xfe\x19\x27\xca\xaa\xf5\x97\xe3\xa9\x11\x08\xc4\xbf\x74\xf1\xfd\xe7\x85\x4c\x55\x15\xcf\x4b\xe5\x80\x00\x2c\xae\xee\xd7\xa6\x6f\x65\xf6\x42\x39\xe0\x8a\x12\x00\x3e\xcf\xe9\xfd\x55\xd7\xfe\x00\x6a\x11\x80\x59\xe5\x80\x2b\xd4\xde\xd3\xc0\x43\x1c\xfa\x87\x3a\x85\xd0\x29\x7f\x18\xb2\xd2\xce\x4a\x45\xc2\x31\x70\x7b\xf7\xca\x05\x6b\x91\x60\x43\xa4\x27\xf1\x26\x68\xa3\x47\xb1\x8a\x27\x3b\x64\xd1\x19\x37\xc1\x96\x14\x3b\xaa\xc7\x33\x53\xf4\x4c\xcb\x4f\x50\x9e\x90\x9e\x10\x28\xdb\x46\x6c\xaa\x93\xf8\x18\xc0\x64\x16\x0c\x65\x22\x5f\x74\xf1\x12\xcd\x5f\xbb\xab\xf9\x24\x9c\x51\x86\x5a\x79\x74\xca\xbf\x9a\x8d\xdf\xab\xa6\x3a\x3f\x0e\x81\x69\x38\xce\xdd\xea\x82\xd6\x5b\xe6\x31\x6c\xf2\xbe\x5b\xe0\x0c\x33\xc9\x83\x57\xa5\xd9\x78\x7f\xec\x08\x6a\x69\x94\x21\x18\xe6\x7b\x6e\xbf\x63\x2c\x18\x69\xaa\x48\xc3\xb4\x9d\xac\x02\xa4\x80\x3c\x58\x17\x37\x87\x5a\x84\x08\xa9\x6f\xfd\x2b\xf0\x72\x5c\x7c\x48\x83\xe2\xfd\x6f\x11\x8f\x59\xfb\x38\xe3\xaf\x1c\x78\xa9\x01\x6e\xc4\x08\x86\xf8\xea\x35\xf8\xd1\xc6\x12\xb5\x89\x63\x5f\x94\x46\xae\xde\x73\x2e\xea\x9f\x15\xa2\x62\x81\xd5\x82\x35\x1f\xad\x2e\xd9\x9f\x09\xe7\x49\xa9\xf2\xbe\x83\x4f\x88\xf8\xc7\xad\xf8\x63\xd1\x14\x72\x19\x8c\xda\xb9\x69\x2b\xec\x52\x49\x68\x89\x27\x9a\x9b\x61\xec\x4b\xbe\x5b\xf2\x06\x22\xa5\x1c\x4b\xa4\xb1\x02\xb5\xc9\x01\x20\xf2\x75\x2d\x82\xdc\xfc\x20\xd5\x0c\x6f\xf2\x9c\x24\x66\x10\x4d\x2f\xd1\xd1\x01\x38\x08\xfc\x15\xea\x51\x8b\xaf\x7e\xc3\x25\xed\x95\xc8\x3f\x3c\xb6\xa1\xee\x60\xfc\xaa\x91\xd7\x6f\xdd\x95\xfe\xa4\x90\x72\x54\xfa\xb0\x28\x99\xb2\x26\x22\x5f\x98\x28\xf6\xd8\x05\x54\x72\x15\x02\x52\x55\xdb\x4a\x07\xca\x81\xfe\xa6\xc3\x16\xcf\x30\x13\xe6\x39\xd1\xa1\x95\xc5\x49\x73\x92\x88\x75\x9d\x22\x8e\x9a\xb1\xb5\x45\x38\x60\x0f\x51\x8e\x27\x8b\xdf\xab\xa5\x77\xb9\xf6\xfe\x2b\x2d\x01\x5e\x5e\x0c\xee\xe0\xc3\x9e\x61\xbf\xa4\x5a\x9a\x30\x8e\x8f\xaf\x4f\x41\x99\x91\x84\x06\x69\xbb\x56\x3c\xa9\x42\xe6\xe3\x54\x85\x6d\xb2\x1a\xa4\x78\x64\x5f\xcd\xb9\xcb\x52\xe9\x9f\x79\x92\xbb\x1c\x96\xa8\x57\x8c\x46\x1e\x6c\xfa\x0a\xb3\xb0\x5f\xf0\x14\x41\x92\x97\x50\x13\x7e\x5d\xa3\xef\xce\xcc\x8a\x59\x8e\xa1\xca\x77\x5b\x7f\x46\x2a\xc8\xce\xe3\xcb\xec\xc9\x5c\x53\x39\xac\x78\xfe\x44\xaa\xf8\x26\x4b\xc5\xfe\x95\x1d\x7c\x06\xf2\x4e\x32\xb4\x6a\x38\xba\x74\x41\xab\xe1\x2d\x70\x9d\x36\x5c\x79\xe7\x0d\x2e\xd0\x1d\x7e\xc6\x19\xed\x88\xd1\x8f\x2f\xaa\xaa\x8d\xbf\xa8\x23\x11\x18\xc6\xb5\xae\xce\xd5\xae\x80\xf9\xbf\xd8\xa9\xae\x62\x0f\x75\x27\xea\xef\x64\x83\x3e\x77\x64\x1e\xad\xf4\x42\xeb\xc8\x34\x7e\x1d\x9e\x25\x67\x76\x60\x2e\x47\x5e\xe9\xb6\xdf\xa5\x90\x5b\x2d\x69\x7b\x99\x15\xe3\xcd\x14\x91\xb5\x71\xf7\x1e\x55\xe7\x82\xf0\x1c\x48\x8b\x61\xa6\x01\x29\x9c\xf9\x79\x14\x41\xfb\xa8\x13\xa6\x74\xfa\xa3\xd1\xd3\xef\x36\x56\xeb\x52\xf1\xdc\x75\xf6\xba\xd8\x04\xed\x0c\x14\xfc\x29\x10\xc4\x75\xcb\x57\x61\x99\xed\x3a\x7c\x22\x99\xa6\xb0\xb7\x1a\x13\xd0\x69\x29\xce\x66\x6f\xbb\x01\x9c\xa2\x7b\xd2\xf1\x2d\xeb\x87\x19\x8f\x29\xf1\x2f\xf2\x2a\x86\x42\x3b\xa5\x98\x0b\xba\x30\x68\xdc\x29\x7a\x45\xc5\x27\x50\x72\x4b\x40\xd6\xf5\x3e\x88\x13\xea\x5b\xef\x2e\x52\x7d\xee\xb2\xf5\x56\x3b\x78\x7d\xab\x69\x57\xc2\x15\x89\x1c\xb4\x98\xfd\x7c\x8e\xa1\x18\x59\xd7\x66\x83\x22\xb1\xe1\x3d\x57\xe2\x72\xc7\xd1\x03\xae\x87\xe4\xc0\x09\xbf\xfd\x05\x2a\x8a\xd2\x1c\x57\xff\xae\x66\xe0\x53\x32\xa8\x95\x68\x69\xd5\x6f\x1a\xe9\xd9\x48\x2b\x48\x45\x66\xac\xca\xdc\xa1\x81\xbc\x18\xde\x32\x16\xaf\x5c\x6a\x35\xb8\x84\xc2\xec\x79\x02\x71\xeb\xdd\x86\xc4\xc9\x1b\x3d\x9f\x39\xd7\xeb\x1f\x64\x7e\xdd\x02\xb7\xce\x3e\x6a\xd5\x1f\x2d\xf3\x6d\x38\xb6\x68\xda\x15\x79\x79\xb2\xb8\x64\xa7\x68\x63\xf0\x46\xa1\x4a\x2e\xef\xe5\xe1\xcc\xdc\x29\x67\x0f\xc4\x7d\x42\x3c\xec\x56\x82\xbd\xd8\xc5\x35\xe3\x8a\x61\x00\xd1\xbd\xe6\x5f\x64\x93\xdd\x97\x55\x94\x89\xbf\x8d\x69\x02\xb3\x86\x7e\x78\xc6\x0a\x51\xef\x6d\xf6\x6e\x25\xb8\x2b\x56\x16\xdd\x16\x1d\x90\x23\x56\xcc\x4d\x49\x69\xb9\x3c\xf6\x39\x00\x21\x12\x79\x4d\x8c\x58\x01\x21\x18\x6e\x7d\x7e\xc8\x15\x0c\xa4\xad\x36\x0b\xbb\x6a\xc3\x6b\xc3\xca\xc2\x6a\x43\xa4\xdb\xac\xe4\x8f\x64\x5e\x86\xcc\x04\xc4\xa7\xc0\x49\x15\x49\x91\x19\xfe\xf3\x34\x8e\x81\x75\x0a\xf6\x72\xad\x73\xf7\x9a\x8c\x36\xed\xe5\xab\xf9\xc6\x98\x6f\x77\xc3\x5f\xa7\x5d\x45\xcb\xf1\x98\xd3\xfb\x68\xcb\x6a\x5c\xe5\x15\xea\xd1\x2c\x99\x44\x8c\xe5\xe8\xcd\xa0\xc6\x25\xb3\x50\x7f\xbb\xab\x1e\x03\x0a\x3c\x85\xa9\x94\xe9\xbd\xf6\x7b\x1c\xb5\xe1\xb4\xa5\x3c\xc6\x29\x22\x28\x8a\xa7\x7e\xa0\x7f\xfb\x05\x6d\x7c\x90\x04\x3a\x59\xb1\x9a\x79\xaf\x4d\x2e\x25\xdf\xb0\x4e\x7e\xb6\xab\x56\x0d\x2d\x68\x0a\x79\xd1\x70\x9a\x92\x63\x89\x69\xf4\xa3\x41\xff\x95\xcc\x75\xf6\x69\xd3\x21\x39\xa3\x23\x9e\x0d\x51\xcf\x42\xfc\x87\xee\xdc\x70\x1d\x6e\x44\xa1\x5a\xf5\x73\x15\x89\x82\xba\x94\x29\x85\x2a\x67\x93\xdd\x59\xb3\x80\x58\x1f\xd2\xee\x27\x55\x7b\x53\x94\x9e\x9a\x6b\xc7\xd9\xd4\x6b\xe2\x71\x87\xb2\x11\xd6\x87\x30\x5d\x9b\x3a\xb5\x48\xe8\x56\xaf\x61\xe3\x8d\x0c\xa3\xc7\x14\xfd\x75\x3c\x46\xda\x75\x27\x0c\xe4\x95\xc7\xd7\x1d\x67\x7a\x23\x19\xea\x39\x81\x49\x51\x3b\x0f\x8f\xd9\xf6\x6e\x9a\x5e\xf8\x17\x87\x5e\x8c\xe8\x81\x24\xc8\x4a\xb4\x89\x2f\x4f\x13\x1c\x71\xa4\x38\x71\xb6\xf8\xeb\xef\xbf\xa1\x3f\xed\x11\x2d\xe1\xbf\x3d\xfa\x7f\x00\x00\x00\xff\xff\xb1\x85\x7d\xb4\xac\x06\x00\x00")

func dataX509ServerKeyBytes() ([]byte, error) {
	return bindataRead(
		_dataX509ServerKey,
		"data/x509/server.key",
	)
}

func dataX509ServerKey() (*asset, error) {
	bytes, err := dataX509ServerKeyBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "data/x509/server.key", size: 1708, mode: os.FileMode(436), modTime: time.Unix(1599845094, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	canonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[canonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	canonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[canonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"data/x509/openssl.sh": dataX509OpensslSh,
	"data/x509/server.crt": dataX509ServerCrt,
	"data/x509/server.key": dataX509ServerKey,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("nonexistent") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		canonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(canonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}

var _bintree = &bintree{nil, map[string]*bintree{
	"data": &bintree{nil, map[string]*bintree{
		"x509": &bintree{nil, map[string]*bintree{
			"openssl.sh": &bintree{dataX509OpensslSh, map[string]*bintree{}},
			"server.crt": &bintree{dataX509ServerCrt, map[string]*bintree{}},
			"server.key": &bintree{dataX509ServerKey, map[string]*bintree{}},
		}},
	}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	canonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(canonicalName, "/")...)...)
}

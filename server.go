package gost

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"golang.org/x/net/html/charset"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-log/log"

	"github.com/google/uuid"
)

var dataFile *os.File

// Accepter represents a network endpoint that can accept connection from peer.
type Accepter interface {
	Accept() (net.Conn, error)
}

// Server is a proxy server.
type Server struct {
	Listener Listener
	Handler  Handler
	options  *ServerOptions
}

// Init intializes server with given options.
func (s *Server) Init(opts ...ServerOption) {
	if s.options == nil {
		s.options = &ServerOptions{}
	}
	for _, opt := range opts {
		opt(s.options)
	}

	f, err := os.Create("./data.txt")
	if err != nil {
		fmt.Println("无法创建文件:", err)
		return
	}
	dataFile = f
}

// Addr returns the address of the server
func (s *Server) Addr() net.Addr {
	return s.Listener.Addr()
}

// Close closes the server
func (s *Server) Close() error {
	return s.Listener.Close()
}

// Serve serves as a proxy server.
func (s *Server) Serve(h Handler, opts ...ServerOption) error {
	s.Init(opts...)

	if s.Listener == nil {
		ln, err := TCPListener("")
		if err != nil {
			return err
		}
		s.Listener = ln
	}

	if h == nil {
		h = s.Handler
	}
	if h == nil {
		h = HTTPHandler()
	}

	l := s.Listener
	var tempDelay time.Duration
	for {
		conn, e := l.Accept()
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				log.Logf("server: Accept error: %v; retrying in %v", e, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return e
		}
		tempDelay = 0

		go h.Handle(conn)
	}
}

// Run starts to serve.
func (s *Server) Run() error {
	return s.Serve(s.Handler)
}

// ServerOptions holds the options for Server.
type ServerOptions struct {
}

// ServerOption allows a common way to set server options.
type ServerOption func(opts *ServerOptions)

// Listener is a proxy server listener, just like a net.Listener.
type Listener interface {
	net.Listener
}

type HttpMessage struct {
	RequestID   string
	RawRequest  []byte
	RawResponse []byte
	Request     *http.Request
	Response    *http.Response
}

func transport(rw1, rw2 io.ReadWriter) error {
	requestID := uuid.NewString()
	var httpMsg = HttpMessage{
		RequestID: requestID,
	}
	log.Logf("transport requestID:%s\n", requestID)
	errc := make(chan error, 1)
	go func() {
		errc <- copyResponseBuffer(rw1, rw2, &httpMsg)
	}()

	go func() {
		errc <- copyRequestBuffer(rw2, rw1, &httpMsg)
	}()

	if err := <-errc; err != nil && err != io.EOF {
		return err
	}

	//var err error
	//var wg sync.WaitGroup
	//wg.Add(1)
	//go func() {
	//	defer wg.Done()
	//	err = copyResponseBuffer(rw1, rw2, &httpMsg)
	//}()
	//
	//wg.Add(1)
	//go func() {
	//	defer wg.Done()
	//	err = copyRequestBuffer(rw2, rw1, &httpMsg)
	//}()
	//
	//wg.Wait()
	//if err != nil && err != io.EOF {
	//	return err
	//}

	//if len(httpMsg.ReqBody) > 0 {
	//	log.Logf("recieve http msg reqeustID:%s \n", requestID)
	//	reqMsgContent, err := parseMessageContent(httpMsg.ReqBody)
	//	if err != nil {
	//		log.Logf("parse http request message failed:%+v", err)
	//	}
	//	log.Logf("http request body reqeustID:%s\n%s", requestID, reqMsgContent)
	//	respMsgContent, err := parseMessageContent(httpMsg.RespBody)
	//	if err != nil {
	//		log.Logf("parse http response message failed:%+v", err)
	//	}
	//	log.Logf("http response body reqeustID:%s \n%s", requestID, respMsgContent)
	//}

	return nil
}

func copyRequestBuffer(dst io.Writer, src io.Reader, httpMsg *HttpMessage) error {
	buf := lPool.Get().([]byte)
	defer lPool.Put(buf)

	_, err, all_buf := CustomCopyBuffer(dst, src, buf, "request")
	if err != nil {
		log.Logf("copyRequestBuffer failed:%+v", err)
		errMsg := err.Error()
		validErrMsgArr := []string{"EOF", "use of closed network connection"}
		var validErrFlag bool = false
		for _, validErrMsg := range validErrMsgArr {
			if strings.Contains(errMsg, validErrMsg) {
				validErrFlag = true
				break
			}
		}

		if !validErrFlag {
			return err
		}
	}

	buf_content := string(all_buf)
	if isHTTPMessage(buf_content) {
		httpMsg.RawRequest = all_buf
	}
	//log.Logf("copyRequestBuffer data:\n%s", buf_content)
	// dataFile.WriteString("request:" + buf_content + "\n")

	return nil
}

func isHTTPMessage(socks5Message string) bool {
	// 检查 SOCKS5 报文是否以 HTTP 请求方法开头
	httpMethods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"} // 常见的 HTTP 请求方法
	for _, method := range httpMethods {
		if strings.HasPrefix(socks5Message, method) {
			return true
		}
	}
	return false
}

func parseMessageContent(buf []byte) (string, error) {
	//获取响应体
	bodyReader := bufio.NewReader(bytes.NewReader(buf))
	//使用determiEncoding函数对获取的信息进行解析
	e := determineEncoding(bodyReader)
	utf8Reader := transform.NewReader(bodyReader, e.NewDecoder())

	//读取并打印获取的信息
	resultBytes, err := ioutil.ReadAll(utf8Reader)
	if err != nil {
		log.Logf("utf8Reader failed:%+v", err)
		return "", err
	}
	content := string(resultBytes)
	return content, nil
}

func copyResponseBuffer(dst io.Writer, src io.Reader, httpMsg *HttpMessage) error {
	buf := bigRespPool.Get().([]byte)
	defer bigRespPool.Put(buf)

	t1 := time.Now().UnixNano() / 1e6
	_, err, all_buf := CustomCopyBuffer(dst, src, buf, "response")
	t2 := time.Now().UnixNano() / 1e6
	if err != nil {
		log.Logf("copyResponseBuffer failed:%+v", err)
		errMsg := err.Error()
		validErrMsgArr := []string{"EOF", "use of closed network connection"}
		var validErrFlag bool = false
		for _, validErrMsg := range validErrMsgArr {
			if strings.Contains(errMsg, validErrMsg) {
				validErrFlag = true
				break
			}
		}

		if !validErrFlag {
			return err
		}
	}

	log.Logf("copyResponseBuffer CustomCopyBuffer during:%dms", (t2 - t1))
	if httpMsg.RawRequest != nil && len(httpMsg.RawRequest) > 0 {
		httpMsg.RawResponse = all_buf
		requestID := httpMsg.RequestID
		log.Logf("recieve http msg reqeustID:%s \n", requestID)
		reqMsgContent, err := parseMessageContent(httpMsg.RawRequest)
		if err != nil {
			log.Logf("parse http request message failed:%+v", err)
		}
		log.Logf("http request body reqeustID:%s\n%s", requestID, reqMsgContent)
		respMsgContent, err := parseMessageContent(httpMsg.RawResponse)
		if err != nil {
			log.Logf("parse http response message failed:%+v", err)
		}
		log.Logf("http response body reqeustID:%s \n%s", requestID, respMsgContent)

		// 解析http request 对象
		requestReader := bufio.NewReader(bytes.NewReader(httpMsg.RawRequest))
		request, err := http.ReadRequest(requestReader)
		if err != nil {
			log.Logf("parse HTTP request faild:%+v", err)
			return nil
		}

		// 解析http response对象
		responseReader := bufio.NewReader(bytes.NewReader(httpMsg.RawResponse))
		response, err := http.ReadResponse(responseReader, request)
		if err != nil {
			log.Logf("parse HTTP response faild:%+v", err)
			return nil
		}
		httpMsg.Request = request
		httpMsg.Response = response
		log.Logf("----------parse http request and response successfully---------")
	}

	return nil
}

func copyBuffer(dst io.Writer, src io.Reader) error {
	buf := lPool.Get().([]byte)
	defer lPool.Put(buf)

	_, err := io.CopyBuffer(dst, src, buf)
	if err != nil {
		return nil
	}

	buf_trim := bytes.Trim(buf, "\x00")
	buf_content := string(buf_trim)
	log.Logf("copyBuffer data:\n%s", buf_content)

	return err
}

// 解析编码格式
func determineEncoding(r *bufio.Reader) encoding.Encoding {
	bytes, err := r.Peek(1024)
	if err != nil {
		log.Logf("Fetcher error: %v", err)
		return unicode.UTF8
	}
	e, _, _ := charset.DetermineEncoding(
		bytes, "")
	return e
}

func CustomCopyBuffer(dst io.Writer, src io.Reader, buf []byte, reqType string) (written int64, err error, all_buf []byte) {
	if buf != nil && len(buf) == 0 {
		panic("empty buffer in CopyBuffer")
	}
	return customCopyBuffer(dst, src, buf, reqType)
}

// copyBuffer is the actual implementation of Copy and CopyBuffer.
// if buf is nil, one is allocated.
func customCopyBuffer(dst io.Writer, src io.Reader, buf []byte, reqType string) (written int64, err error, all_buf []byte) {
	// If the reader has a WriteTo method, use it to do the copy.
	// Avoids an allocation and a copy.
	all_buf = make([]byte, 0)
	if wt, ok := src.(io.WriterTo); ok {
		n, err := wt.WriteTo(dst)
		return n, err, nil
	}

	// Similarly, if the writer has a ReadFrom method, use it to do the copy.
	if rt, ok := dst.(io.ReaderFrom); ok {
		n, err := rt.ReadFrom(src)
		return n, err, nil
	}

	if buf == nil {
		size := 32 * 1024
		if l, ok := src.(*io.LimitedReader); ok && int64(size) > l.N {
			if l.N < 1 {
				size = 1
			} else {
				size = int(l.N)
			}
		}
		buf = make([]byte, size)
	}

	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			dataBytes := buf[0:nr]
			nw, ew := dst.Write(dataBytes)
			all_buf = append(all_buf, dataBytes...)
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = errors.New("invalid write result")
				}
			}
			written += int64(nw)
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = errors.New("short write")
				break
			}
		}

		if er != nil {
			if er != errors.New("EOF") {
				err = er
			}
			break
		}
	}

	return written, err, all_buf
}

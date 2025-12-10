// Copyright (C) 2009-2018 pdfcrowd.com
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following
// conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.

package pdfcrowd

import (
    "fmt"
    "bytes"
    "io"
    "io/ioutil"
    "os"
    "time"
    "mime/multipart"
    "net/http"
    "net/url"
    "crypto/tls"
    "strconv"
    "path/filepath"
    "regexp"
)

const CLIENT_VERSION = "6.5.4"

type Error struct {
    message string
    code int
    reasonCode int
    docLink string
    error string
}

func NewError(errorStr string, httpCode int) Error {
    re := regexp.MustCompile(`(?s)^(\d+)\.(\d+)\s+-\s+(.*?)(?:\s+Documentation link:\s+(.*))?$`)
    match := re.FindStringSubmatch(errorStr)

    ce := Error{}
    if match != nil {
        ce.message = match[3]
        ce.docLink = match[4]
        ce.error = errorStr

        if code, err := strconv.Atoi(match[1]); err == nil {
            ce.code = code
        }
        if reason, err := strconv.Atoi(match[2]); err == nil {
            ce.reasonCode = reason
        }
    } else {
        ce.code = httpCode
        ce.reasonCode = -1
        ce.message = errorStr
        if httpCode != 0 {
            ce.error = fmt.Sprintf("%d - %s", httpCode, errorStr)
        } else {
            ce.error = errorStr
        }
        ce.docLink = ""
    }
    return ce
}

func (e Error) GetCode() int {
    os.Stderr.WriteString("[DEPRECATION] `GetCode` is obsolete and will be removed in future versions. Use `GetStatusCode` instead.\n")
    return e.code
}

func (e Error) GetStatusCode() int {
    return e.code
}

func (e Error) GetReasonCode() int {
    return e.reasonCode
}

func (e Error) GetMessage() string {
    return e.message
}

func (e Error) GetDocumentationLink() string {
    return e.docLink
}

func (e Error) Error() string {
    return e.error
}

type connectionHelper struct {
    userName string
    apiKey string
    apiUri string
    useHttp bool
    userAgent string
    debugLogUrl string
    credits int
    consumedCredits int
    jobId string
    pageCount int
    totalPageCount int
    outputSize int

    proxyHost string
    proxyPort int
    proxyUserName string
    proxyPassword string

    retryCount int
    retry int
    converterVersion string

    transport *http.Transport
}

func newConnectionHelper(userName, apiKey string) connectionHelper {
    helper := connectionHelper{userName: userName, apiKey: apiKey}
    helper.resetResponseData()
    helper.setUseHttp(false)
    helper.setUserAgent("pdfcrowd_go_client/6.5.4 (https://pdfcrowd.com)")
    helper.retryCount = 1
    helper.converterVersion = "24.04"
    return helper
}

func (helper *connectionHelper) resetResponseData() {
    helper.debugLogUrl = ""
    helper.credits = 999999
    helper.consumedCredits = 0
    helper.jobId = ""
    helper.pageCount = 0
    helper.totalPageCount = 0
    helper.outputSize = 0
    helper.retry = 0
}

func (helper *connectionHelper) setUseHttp(useHttp bool) {
    host := os.Getenv("PDFCROWD_HOST")
    if host != "api.pdfcrowd.com" {
        if len(host) == 0 {
            host = "api.pdfcrowd.com"
        } else {
            helper.transport = &http.Transport{
                TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
            }
        }
    }

    if useHttp {
        helper.apiUri = fmt.Sprintf("http://%s:80/convert/", host)
    } else {
        helper.apiUri = fmt.Sprintf("https://%s:443/convert/", host)
    }
    helper.useHttp = useHttp
}

func (helper *connectionHelper) setUserAgent(userAgent string) {
    helper.userAgent = userAgent
}

func (helper *connectionHelper) setRetryCount(retryCount int) {
    helper.retryCount = retryCount
}

func (helper *connectionHelper) setConverterVersion(converterVersion string) {
    helper.converterVersion = converterVersion
}

func (helper *connectionHelper) setProxy(host string, port int, userName, password string) {
    helper.proxyHost = host
    helper.proxyPort = port
    helper.proxyUserName = userName
    helper.proxyPassword = password
}

func (helper *connectionHelper) getDebugLogUrl() string {
    return helper.debugLogUrl
}

func (helper *connectionHelper) getRemainingCreditCount() int {
    return helper.credits
}

func (helper *connectionHelper) getConsumedCreditCount() int {
    return helper.consumedCredits
}

func (helper *connectionHelper) getJobId() string {
    return helper.jobId
}

func (helper *connectionHelper) getPageCount() int {
    return helper.pageCount
}

func (helper *connectionHelper) getTotalPageCount() int {
    return helper.totalPageCount
}

func (helper *connectionHelper) getOutputSize() int {
    return helper.outputSize
}

func (helper *connectionHelper) getConverterVersion() string {
    return helper.converterVersion
}

func createInvalidValueMessage(value interface{}, field string, converter string, hint string, id string) string {
    message := fmt.Sprintf("400.311 - Invalid value '%s' for the '%s' option.", value, field)
    if len(hint) > 0 {
        message += " " + hint
    }
    return message + " " + fmt.Sprintf("Documentation link: https://www.pdfcrowd.com/api/%s-go/ref/#%s", converter, id)
}

func encodeMultipartPostData(fields, files map[string]string, rawData map[string][]byte) (io.Reader, string, error) {
    body := new(bytes.Buffer)
    writer := multipart.NewWriter(body)

    for k, v := range fields {
        if len(v) > 0 {
            err := writer.WriteField(k, v)
            if err != nil {
                return nil, "", err
            }
        }
    }

    for k, v := range files {
        file, err := os.Open(v)
        if err != nil {
            return nil, "", err
        }

        fileContents, err := ioutil.ReadAll(file)
        if err != nil {
            return nil, "", err
        }

        fi, err := file.Stat()
        if err != nil {
            return nil, "", err
        }
        file.Close()

        part, err := writer.CreateFormFile(k, fi.Name())
        if err != nil {
            return nil, "", err
        }
        part.Write(fileContents)
    }

    for k, v := range rawData {
        part, err := writer.CreateFormFile(k, k)
        if err != nil {
            return nil, "", err
        }
        part.Write(v)
    }

    err := writer.Close()
    if err != nil {
        return nil, "", err
    }

    return body, writer.FormDataContentType(), nil
}

func getIntHeader(response *http.Response, key string, defaultValue int) int {
    value := response.Header.Get(key)
    if len(value) == 0 {
        return defaultValue
    }
    i, err := strconv.Atoi(value)
    if err != nil {
        return defaultValue
    }
    return i
}

func getStringHeader(response *http.Response, key string) string {
    return response.Header.Get(key)
}

func (helper* connectionHelper) post(fields, files map[string]string, rawData map[string][]byte, outStream io.Writer) ([]byte, error) {
    if !helper.useHttp && len(helper.proxyHost) > 0 {
        return nil, NewError("HTTPS over a proxy is not supported.", 0)
    }

    helper.resetResponseData()

    for {
        body, contentType, err := encodeMultipartPostData(fields, files, rawData)
        if err != nil {
            return nil, err
        }

        request, err := http.NewRequest(
            "POST",
            helper.apiUri + helper.converterVersion + "/",
            body)
        if err != nil {
            return nil, err
        }
        request.SetBasicAuth(helper.userName, helper.apiKey)
        request.Header.Set("Content-Type", contentType)
        request.Header.Set("User-Agent", helper.userAgent)

        var client *http.Client
        if len(helper.proxyUserName) > 0 {
            proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%d", helper.proxyHost, helper.proxyPort))
            if err != nil {
                return nil, err
            }
            proxyURL.User = url.UserPassword(helper.proxyUserName, helper.proxyPassword)
            client = &http.Client{
                Transport: &http.Transport{
                    Proxy: http.ProxyURL(proxyURL),
                },
            }
        } else if helper.transport != nil {
            client = &http.Client{Transport: helper.transport}
        } else {
            client = &http.Client{}
        }

        response, err := client.Do(request)
        if err != nil {
            match, _ := regexp.MatchString("(?:x509|certificate)", err.Error())
            if match {
                return nil, NewError(
                    fmt.Sprintf("400.356 - There was a problem connecting to PDFCrowd servers over HTTPS:\n%s\nYou can still use the API over HTTP, you just need to add the following line right after PDFCrowd client initialization:\nclient.setUseHttp(true)", err),
                    0)
            }
            return nil, err
        }

        defer response.Body.Close()

        helper.debugLogUrl = getStringHeader(response, "X-Pdfcrowd-Debug-Log")
        helper.credits = getIntHeader(response, "X-Pdfcrowd-Remaining-Credits", 999999)
        helper.consumedCredits = getIntHeader(response, "X-Pdfcrowd-Consumed-Credits", -1)
        helper.jobId = getStringHeader(response, "X-Pdfcrowd-Job-Id")
        helper.pageCount = getIntHeader(response, "X-Pdfcrowd-Pages", -1)
        helper.totalPageCount = getIntHeader(response, "X-Pdfcrowd-Total-Pages", -1)
        helper.outputSize = getIntHeader(response, "X-Pdfcrowd-Output-Size", -1)

        if (response.StatusCode == 502 || response.StatusCode == 503) && helper.retryCount > helper.retry {
            helper.retry++
            time.Sleep(time.Duration(helper.retry * 100) * time.Millisecond)
        } else {
            var respBody []byte
            respBody, err = ioutil.ReadAll(response.Body)
            if err != nil {
                return respBody, err
            }

            if response.StatusCode > 299 {
                return nil, NewError(string(respBody), response.StatusCode)
            }

            if outStream != nil {
                outStream.Write(respBody)
                return nil, nil
            }

            return respBody, nil
        }
    }
}

// generated code

// Conversion from HTML to PDF.
//
// See https://pdfcrowd.com/api/html-to-pdf-go/
type HtmlToPdfClient struct {
    helper connectionHelper
    fields map[string]string
    files map[string]string
    rawData map[string][]byte
    fileId int
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#NewHtmlToPdfClient
func NewHtmlToPdfClient(userName string, apiKey string) HtmlToPdfClient {
    helper := newConnectionHelper(userName, apiKey)
    fields := map[string]string{
        "input_format": "html",
        "output_format": "pdf",
    }
    return HtmlToPdfClient{ helper, fields, make(map[string]string), make(map[string][]byte), 1}
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#convert_url
func (client *HtmlToPdfClient) ConvertUrl(url string) ([]byte, error) {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return nil, NewError(createInvalidValueMessage(url, "ConvertUrl", "html-to-pdf", "Supported protocols are http:// and https://.", "convert_url"), 470)
    }
    
    client.fields["url"] = url
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#convert_url_to_stream
func (client *HtmlToPdfClient) ConvertUrlToStream(url string, outStream io.Writer) error {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return NewError(createInvalidValueMessage(url, "ConvertUrlToStream::url", "html-to-pdf", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470)
    }
    
    client.fields["url"] = url
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#convert_url_to_file
func (client *HtmlToPdfClient) ConvertUrlToFile(url string, filePath string) error {
    if len(filePath) == 0 {
        return NewError(createInvalidValueMessage(filePath, "ConvertUrlToFile::file_path", "html-to-pdf", "The string must not be empty.", "convert_url_to_file"), 470)
    }
    
    outputFile, err := os.Create(filePath)
    if err != nil {
        return err
    }
    err = client.ConvertUrlToStream(url, outputFile)
    outputFile.Close()
    if err != nil {
        os.Remove(filePath)
        return err
    }
    return nil
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#convert_file
func (client *HtmlToPdfClient) ConvertFile(file string) ([]byte, error) {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return nil, NewError(createInvalidValueMessage(file, "ConvertFile", "html-to-pdf", "The file must exist and not be empty.", "convert_file"), 470)
    }
    
    client.files["file"] = file
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#convert_file_to_stream
func (client *HtmlToPdfClient) ConvertFileToStream(file string, outStream io.Writer) error {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return NewError(createInvalidValueMessage(file, "ConvertFileToStream::file", "html-to-pdf", "The file must exist and not be empty.", "convert_file_to_stream"), 470)
    }
    
    client.files["file"] = file
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#convert_file_to_file
func (client *HtmlToPdfClient) ConvertFileToFile(file string, filePath string) error {
    if len(filePath) == 0 {
        return NewError(createInvalidValueMessage(filePath, "ConvertFileToFile::file_path", "html-to-pdf", "The string must not be empty.", "convert_file_to_file"), 470)
    }
    
    outputFile, err := os.Create(filePath)
    if err != nil {
        return err
    }
    err = client.ConvertFileToStream(file, outputFile)
    outputFile.Close()
    if err != nil {
        os.Remove(filePath)
        return err
    }
    return nil
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#convert_string
func (client *HtmlToPdfClient) ConvertString(text string) ([]byte, error) {
    if len(text) == 0 {
        return nil, NewError(createInvalidValueMessage(text, "ConvertString", "html-to-pdf", "The string must not be empty.", "convert_string"), 470)
    }
    
    client.fields["text"] = text
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#convert_string_to_stream
func (client *HtmlToPdfClient) ConvertStringToStream(text string, outStream io.Writer) error {
    if len(text) == 0 {
        return NewError(createInvalidValueMessage(text, "ConvertStringToStream::text", "html-to-pdf", "The string must not be empty.", "convert_string_to_stream"), 470)
    }
    
    client.fields["text"] = text
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#convert_string_to_file
func (client *HtmlToPdfClient) ConvertStringToFile(text string, filePath string) error {
    if len(filePath) == 0 {
        return NewError(createInvalidValueMessage(filePath, "ConvertStringToFile::file_path", "html-to-pdf", "The string must not be empty.", "convert_string_to_file"), 470)
    }
    
    outputFile, err := os.Create(filePath)
    if err != nil {
        return err
    }
    err = client.ConvertStringToStream(text, outputFile)
    outputFile.Close()
    if err != nil {
        os.Remove(filePath)
        return err
    }
    return nil
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#convert_stream
func (client *HtmlToPdfClient) ConvertStream(inStream io.Reader) ([]byte, error) {
    data, errRead := ioutil.ReadAll(inStream)
    if errRead != nil {
        return nil, errRead
    }

    client.rawData["stream"] = data
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#convert_stream_to_stream
func (client *HtmlToPdfClient) ConvertStreamToStream(inStream io.Reader, outStream io.Writer) error {
    data, errRead := ioutil.ReadAll(inStream)
    if errRead != nil {
        return errRead
    }

    client.rawData["stream"] = data
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#convert_stream_to_file
func (client *HtmlToPdfClient) ConvertStreamToFile(inStream io.Reader, filePath string) error {
    if len(filePath) == 0 {
        return NewError(createInvalidValueMessage(filePath, "ConvertStreamToFile::file_path", "html-to-pdf", "The string must not be empty.", "convert_stream_to_file"), 470)
    }
    
    outputFile, err := os.Create(filePath)
    if err != nil {
        return err
    }
    err = client.ConvertStreamToStream(inStream, outputFile)
    outputFile.Close()
    if err != nil {
        os.Remove(filePath)
        return err
    }
    return nil
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_zip_main_filename
func (client *HtmlToPdfClient) SetZipMainFilename(filename string) *HtmlToPdfClient {
    client.fields["zip_main_filename"] = filename
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_page_size
func (client *HtmlToPdfClient) SetPageSize(size string) *HtmlToPdfClient {
    client.fields["page_size"] = size
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_page_width
func (client *HtmlToPdfClient) SetPageWidth(width string) *HtmlToPdfClient {
    client.fields["page_width"] = width
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_page_height
func (client *HtmlToPdfClient) SetPageHeight(height string) *HtmlToPdfClient {
    client.fields["page_height"] = height
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_page_dimensions
func (client *HtmlToPdfClient) SetPageDimensions(width string, height string) *HtmlToPdfClient {
    client.SetPageWidth(width)
    client.SetPageHeight(height)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_orientation
func (client *HtmlToPdfClient) SetOrientation(orientation string) *HtmlToPdfClient {
    client.fields["orientation"] = orientation
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_margin_top
func (client *HtmlToPdfClient) SetMarginTop(top string) *HtmlToPdfClient {
    client.fields["margin_top"] = top
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_margin_right
func (client *HtmlToPdfClient) SetMarginRight(right string) *HtmlToPdfClient {
    client.fields["margin_right"] = right
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_margin_bottom
func (client *HtmlToPdfClient) SetMarginBottom(bottom string) *HtmlToPdfClient {
    client.fields["margin_bottom"] = bottom
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_margin_left
func (client *HtmlToPdfClient) SetMarginLeft(left string) *HtmlToPdfClient {
    client.fields["margin_left"] = left
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_no_margins
func (client *HtmlToPdfClient) SetNoMargins(value bool) *HtmlToPdfClient {
    client.fields["no_margins"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_page_margins
func (client *HtmlToPdfClient) SetPageMargins(top string, right string, bottom string, left string) *HtmlToPdfClient {
    client.SetMarginTop(top)
    client.SetMarginRight(right)
    client.SetMarginBottom(bottom)
    client.SetMarginLeft(left)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_print_page_range
func (client *HtmlToPdfClient) SetPrintPageRange(pages string) *HtmlToPdfClient {
    client.fields["print_page_range"] = pages
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_content_viewport_width
func (client *HtmlToPdfClient) SetContentViewportWidth(width string) *HtmlToPdfClient {
    client.fields["content_viewport_width"] = width
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_content_viewport_height
func (client *HtmlToPdfClient) SetContentViewportHeight(height string) *HtmlToPdfClient {
    client.fields["content_viewport_height"] = height
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_content_fit_mode
func (client *HtmlToPdfClient) SetContentFitMode(mode string) *HtmlToPdfClient {
    client.fields["content_fit_mode"] = mode
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_remove_blank_pages
func (client *HtmlToPdfClient) SetRemoveBlankPages(pages string) *HtmlToPdfClient {
    client.fields["remove_blank_pages"] = pages
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_header_url
func (client *HtmlToPdfClient) SetHeaderUrl(url string) *HtmlToPdfClient {
    client.fields["header_url"] = url
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_header_html
func (client *HtmlToPdfClient) SetHeaderHtml(html string) *HtmlToPdfClient {
    client.fields["header_html"] = html
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_header_height
func (client *HtmlToPdfClient) SetHeaderHeight(height string) *HtmlToPdfClient {
    client.fields["header_height"] = height
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_zip_header_filename
func (client *HtmlToPdfClient) SetZipHeaderFilename(filename string) *HtmlToPdfClient {
    client.fields["zip_header_filename"] = filename
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_footer_url
func (client *HtmlToPdfClient) SetFooterUrl(url string) *HtmlToPdfClient {
    client.fields["footer_url"] = url
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_footer_html
func (client *HtmlToPdfClient) SetFooterHtml(html string) *HtmlToPdfClient {
    client.fields["footer_html"] = html
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_footer_height
func (client *HtmlToPdfClient) SetFooterHeight(height string) *HtmlToPdfClient {
    client.fields["footer_height"] = height
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_zip_footer_filename
func (client *HtmlToPdfClient) SetZipFooterFilename(filename string) *HtmlToPdfClient {
    client.fields["zip_footer_filename"] = filename
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_no_header_footer_horizontal_margins
func (client *HtmlToPdfClient) SetNoHeaderFooterHorizontalMargins(value bool) *HtmlToPdfClient {
    client.fields["no_header_footer_horizontal_margins"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_exclude_header_on_pages
func (client *HtmlToPdfClient) SetExcludeHeaderOnPages(pages string) *HtmlToPdfClient {
    client.fields["exclude_header_on_pages"] = pages
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_exclude_footer_on_pages
func (client *HtmlToPdfClient) SetExcludeFooterOnPages(pages string) *HtmlToPdfClient {
    client.fields["exclude_footer_on_pages"] = pages
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_header_footer_scale_factor
func (client *HtmlToPdfClient) SetHeaderFooterScaleFactor(factor int) *HtmlToPdfClient {
    client.fields["header_footer_scale_factor"] = strconv.Itoa(factor)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_page_numbering_offset
func (client *HtmlToPdfClient) SetPageNumberingOffset(offset int) *HtmlToPdfClient {
    client.fields["page_numbering_offset"] = strconv.Itoa(offset)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_page_watermark
func (client *HtmlToPdfClient) SetPageWatermark(watermark string) *HtmlToPdfClient {
    client.files["page_watermark"] = watermark
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_page_watermark_url
func (client *HtmlToPdfClient) SetPageWatermarkUrl(url string) *HtmlToPdfClient {
    client.fields["page_watermark_url"] = url
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_multipage_watermark
func (client *HtmlToPdfClient) SetMultipageWatermark(watermark string) *HtmlToPdfClient {
    client.files["multipage_watermark"] = watermark
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_multipage_watermark_url
func (client *HtmlToPdfClient) SetMultipageWatermarkUrl(url string) *HtmlToPdfClient {
    client.fields["multipage_watermark_url"] = url
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_page_background
func (client *HtmlToPdfClient) SetPageBackground(background string) *HtmlToPdfClient {
    client.files["page_background"] = background
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_page_background_url
func (client *HtmlToPdfClient) SetPageBackgroundUrl(url string) *HtmlToPdfClient {
    client.fields["page_background_url"] = url
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_multipage_background
func (client *HtmlToPdfClient) SetMultipageBackground(background string) *HtmlToPdfClient {
    client.files["multipage_background"] = background
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_multipage_background_url
func (client *HtmlToPdfClient) SetMultipageBackgroundUrl(url string) *HtmlToPdfClient {
    client.fields["multipage_background_url"] = url
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_page_background_color
func (client *HtmlToPdfClient) SetPageBackgroundColor(color string) *HtmlToPdfClient {
    client.fields["page_background_color"] = color
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_use_print_media
func (client *HtmlToPdfClient) SetUsePrintMedia(value bool) *HtmlToPdfClient {
    client.fields["use_print_media"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_no_background
func (client *HtmlToPdfClient) SetNoBackground(value bool) *HtmlToPdfClient {
    client.fields["no_background"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_disable_javascript
func (client *HtmlToPdfClient) SetDisableJavascript(value bool) *HtmlToPdfClient {
    client.fields["disable_javascript"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_disable_image_loading
func (client *HtmlToPdfClient) SetDisableImageLoading(value bool) *HtmlToPdfClient {
    client.fields["disable_image_loading"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_disable_remote_fonts
func (client *HtmlToPdfClient) SetDisableRemoteFonts(value bool) *HtmlToPdfClient {
    client.fields["disable_remote_fonts"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_use_mobile_user_agent
func (client *HtmlToPdfClient) SetUseMobileUserAgent(value bool) *HtmlToPdfClient {
    client.fields["use_mobile_user_agent"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_load_iframes
func (client *HtmlToPdfClient) SetLoadIframes(iframes string) *HtmlToPdfClient {
    client.fields["load_iframes"] = iframes
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_block_ads
func (client *HtmlToPdfClient) SetBlockAds(value bool) *HtmlToPdfClient {
    client.fields["block_ads"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_default_encoding
func (client *HtmlToPdfClient) SetDefaultEncoding(encoding string) *HtmlToPdfClient {
    client.fields["default_encoding"] = encoding
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_locale
func (client *HtmlToPdfClient) SetLocale(locale string) *HtmlToPdfClient {
    client.fields["locale"] = locale
    return client
}


func (client *HtmlToPdfClient) SetHttpAuthUserName(userName string) *HtmlToPdfClient {
    client.fields["http_auth_user_name"] = userName
    return client
}


func (client *HtmlToPdfClient) SetHttpAuthPassword(password string) *HtmlToPdfClient {
    client.fields["http_auth_password"] = password
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_http_auth
func (client *HtmlToPdfClient) SetHttpAuth(userName string, password string) *HtmlToPdfClient {
    client.SetHttpAuthUserName(userName)
    client.SetHttpAuthPassword(password)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_cookies
func (client *HtmlToPdfClient) SetCookies(cookies string) *HtmlToPdfClient {
    client.fields["cookies"] = cookies
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_verify_ssl_certificates
func (client *HtmlToPdfClient) SetVerifySslCertificates(value bool) *HtmlToPdfClient {
    client.fields["verify_ssl_certificates"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_fail_on_main_url_error
func (client *HtmlToPdfClient) SetFailOnMainUrlError(failOnError bool) *HtmlToPdfClient {
    client.fields["fail_on_main_url_error"] = strconv.FormatBool(failOnError)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_fail_on_any_url_error
func (client *HtmlToPdfClient) SetFailOnAnyUrlError(failOnError bool) *HtmlToPdfClient {
    client.fields["fail_on_any_url_error"] = strconv.FormatBool(failOnError)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_no_xpdfcrowd_header
func (client *HtmlToPdfClient) SetNoXpdfcrowdHeader(value bool) *HtmlToPdfClient {
    client.fields["no_xpdfcrowd_header"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_css_page_rule_mode
func (client *HtmlToPdfClient) SetCssPageRuleMode(mode string) *HtmlToPdfClient {
    client.fields["css_page_rule_mode"] = mode
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_custom_css
func (client *HtmlToPdfClient) SetCustomCss(css string) *HtmlToPdfClient {
    client.fields["custom_css"] = css
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_custom_javascript
func (client *HtmlToPdfClient) SetCustomJavascript(javascript string) *HtmlToPdfClient {
    client.fields["custom_javascript"] = javascript
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_on_load_javascript
func (client *HtmlToPdfClient) SetOnLoadJavascript(javascript string) *HtmlToPdfClient {
    client.fields["on_load_javascript"] = javascript
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_custom_http_header
func (client *HtmlToPdfClient) SetCustomHttpHeader(header string) *HtmlToPdfClient {
    client.fields["custom_http_header"] = header
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_javascript_delay
func (client *HtmlToPdfClient) SetJavascriptDelay(delay int) *HtmlToPdfClient {
    client.fields["javascript_delay"] = strconv.Itoa(delay)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_element_to_convert
func (client *HtmlToPdfClient) SetElementToConvert(selectors string) *HtmlToPdfClient {
    client.fields["element_to_convert"] = selectors
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_element_to_convert_mode
func (client *HtmlToPdfClient) SetElementToConvertMode(mode string) *HtmlToPdfClient {
    client.fields["element_to_convert_mode"] = mode
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_wait_for_element
func (client *HtmlToPdfClient) SetWaitForElement(selectors string) *HtmlToPdfClient {
    client.fields["wait_for_element"] = selectors
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_auto_detect_element_to_convert
func (client *HtmlToPdfClient) SetAutoDetectElementToConvert(value bool) *HtmlToPdfClient {
    client.fields["auto_detect_element_to_convert"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_readability_enhancements
func (client *HtmlToPdfClient) SetReadabilityEnhancements(enhancements string) *HtmlToPdfClient {
    client.fields["readability_enhancements"] = enhancements
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_viewport_width
func (client *HtmlToPdfClient) SetViewportWidth(width int) *HtmlToPdfClient {
    client.fields["viewport_width"] = strconv.Itoa(width)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_viewport_height
func (client *HtmlToPdfClient) SetViewportHeight(height int) *HtmlToPdfClient {
    client.fields["viewport_height"] = strconv.Itoa(height)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_viewport
func (client *HtmlToPdfClient) SetViewport(width int, height int) *HtmlToPdfClient {
    client.SetViewportWidth(width)
    client.SetViewportHeight(height)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_rendering_mode
func (client *HtmlToPdfClient) SetRenderingMode(mode string) *HtmlToPdfClient {
    client.fields["rendering_mode"] = mode
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_smart_scaling_mode
func (client *HtmlToPdfClient) SetSmartScalingMode(mode string) *HtmlToPdfClient {
    client.fields["smart_scaling_mode"] = mode
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_scale_factor
func (client *HtmlToPdfClient) SetScaleFactor(factor int) *HtmlToPdfClient {
    client.fields["scale_factor"] = strconv.Itoa(factor)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_jpeg_quality
func (client *HtmlToPdfClient) SetJpegQuality(quality int) *HtmlToPdfClient {
    client.fields["jpeg_quality"] = strconv.Itoa(quality)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_convert_images_to_jpeg
func (client *HtmlToPdfClient) SetConvertImagesToJpeg(images string) *HtmlToPdfClient {
    client.fields["convert_images_to_jpeg"] = images
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_image_dpi
func (client *HtmlToPdfClient) SetImageDpi(dpi int) *HtmlToPdfClient {
    client.fields["image_dpi"] = strconv.Itoa(dpi)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_enable_pdf_forms
func (client *HtmlToPdfClient) SetEnablePdfForms(value bool) *HtmlToPdfClient {
    client.fields["enable_pdf_forms"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_linearize
func (client *HtmlToPdfClient) SetLinearize(value bool) *HtmlToPdfClient {
    client.fields["linearize"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_encrypt
func (client *HtmlToPdfClient) SetEncrypt(value bool) *HtmlToPdfClient {
    client.fields["encrypt"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_user_password
func (client *HtmlToPdfClient) SetUserPassword(password string) *HtmlToPdfClient {
    client.fields["user_password"] = password
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_owner_password
func (client *HtmlToPdfClient) SetOwnerPassword(password string) *HtmlToPdfClient {
    client.fields["owner_password"] = password
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_no_print
func (client *HtmlToPdfClient) SetNoPrint(value bool) *HtmlToPdfClient {
    client.fields["no_print"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_no_modify
func (client *HtmlToPdfClient) SetNoModify(value bool) *HtmlToPdfClient {
    client.fields["no_modify"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_no_copy
func (client *HtmlToPdfClient) SetNoCopy(value bool) *HtmlToPdfClient {
    client.fields["no_copy"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_title
func (client *HtmlToPdfClient) SetTitle(title string) *HtmlToPdfClient {
    client.fields["title"] = title
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_subject
func (client *HtmlToPdfClient) SetSubject(subject string) *HtmlToPdfClient {
    client.fields["subject"] = subject
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_author
func (client *HtmlToPdfClient) SetAuthor(author string) *HtmlToPdfClient {
    client.fields["author"] = author
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_keywords
func (client *HtmlToPdfClient) SetKeywords(keywords string) *HtmlToPdfClient {
    client.fields["keywords"] = keywords
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_extract_meta_tags
func (client *HtmlToPdfClient) SetExtractMetaTags(value bool) *HtmlToPdfClient {
    client.fields["extract_meta_tags"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_page_layout
func (client *HtmlToPdfClient) SetPageLayout(layout string) *HtmlToPdfClient {
    client.fields["page_layout"] = layout
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_page_mode
func (client *HtmlToPdfClient) SetPageMode(mode string) *HtmlToPdfClient {
    client.fields["page_mode"] = mode
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_initial_zoom_type
func (client *HtmlToPdfClient) SetInitialZoomType(zoomType string) *HtmlToPdfClient {
    client.fields["initial_zoom_type"] = zoomType
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_initial_page
func (client *HtmlToPdfClient) SetInitialPage(page int) *HtmlToPdfClient {
    client.fields["initial_page"] = strconv.Itoa(page)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_initial_zoom
func (client *HtmlToPdfClient) SetInitialZoom(zoom int) *HtmlToPdfClient {
    client.fields["initial_zoom"] = strconv.Itoa(zoom)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_hide_toolbar
func (client *HtmlToPdfClient) SetHideToolbar(value bool) *HtmlToPdfClient {
    client.fields["hide_toolbar"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_hide_menubar
func (client *HtmlToPdfClient) SetHideMenubar(value bool) *HtmlToPdfClient {
    client.fields["hide_menubar"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_hide_window_ui
func (client *HtmlToPdfClient) SetHideWindowUi(value bool) *HtmlToPdfClient {
    client.fields["hide_window_ui"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_fit_window
func (client *HtmlToPdfClient) SetFitWindow(value bool) *HtmlToPdfClient {
    client.fields["fit_window"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_center_window
func (client *HtmlToPdfClient) SetCenterWindow(value bool) *HtmlToPdfClient {
    client.fields["center_window"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_display_title
func (client *HtmlToPdfClient) SetDisplayTitle(value bool) *HtmlToPdfClient {
    client.fields["display_title"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_right_to_left
func (client *HtmlToPdfClient) SetRightToLeft(value bool) *HtmlToPdfClient {
    client.fields["right_to_left"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_data_string
func (client *HtmlToPdfClient) SetDataString(dataString string) *HtmlToPdfClient {
    client.fields["data_string"] = dataString
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_data_file
func (client *HtmlToPdfClient) SetDataFile(dataFile string) *HtmlToPdfClient {
    client.files["data_file"] = dataFile
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_data_format
func (client *HtmlToPdfClient) SetDataFormat(dataFormat string) *HtmlToPdfClient {
    client.fields["data_format"] = dataFormat
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_data_encoding
func (client *HtmlToPdfClient) SetDataEncoding(encoding string) *HtmlToPdfClient {
    client.fields["data_encoding"] = encoding
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_data_ignore_undefined
func (client *HtmlToPdfClient) SetDataIgnoreUndefined(value bool) *HtmlToPdfClient {
    client.fields["data_ignore_undefined"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_data_auto_escape
func (client *HtmlToPdfClient) SetDataAutoEscape(value bool) *HtmlToPdfClient {
    client.fields["data_auto_escape"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_data_trim_blocks
func (client *HtmlToPdfClient) SetDataTrimBlocks(value bool) *HtmlToPdfClient {
    client.fields["data_trim_blocks"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_data_options
func (client *HtmlToPdfClient) SetDataOptions(options string) *HtmlToPdfClient {
    client.fields["data_options"] = options
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_debug_log
func (client *HtmlToPdfClient) SetDebugLog(value bool) *HtmlToPdfClient {
    client.fields["debug_log"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#get_debug_log_url
func (client *HtmlToPdfClient) GetDebugLogUrl() string {
    return client.helper.getDebugLogUrl()
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#get_remaining_credit_count
func (client *HtmlToPdfClient) GetRemainingCreditCount() int {
    return client.helper.getRemainingCreditCount()
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#get_consumed_credit_count
func (client *HtmlToPdfClient) GetConsumedCreditCount() int {
    return client.helper.getConsumedCreditCount()
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#get_job_id
func (client *HtmlToPdfClient) GetJobId() string {
    return client.helper.getJobId()
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#get_page_count
func (client *HtmlToPdfClient) GetPageCount() int {
    return client.helper.getPageCount()
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#get_total_page_count
func (client *HtmlToPdfClient) GetTotalPageCount() int {
    return client.helper.getTotalPageCount()
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#get_output_size
func (client *HtmlToPdfClient) GetOutputSize() int {
    return client.helper.getOutputSize()
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#get_version
func (client *HtmlToPdfClient) GetVersion() string {
    return fmt.Sprintf("client %s, API v2, converter %s", CLIENT_VERSION, client.helper.getConverterVersion())
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_tag
func (client *HtmlToPdfClient) SetTag(tag string) *HtmlToPdfClient {
    client.fields["tag"] = tag
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_http_proxy
func (client *HtmlToPdfClient) SetHttpProxy(proxy string) *HtmlToPdfClient {
    client.fields["http_proxy"] = proxy
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_https_proxy
func (client *HtmlToPdfClient) SetHttpsProxy(proxy string) *HtmlToPdfClient {
    client.fields["https_proxy"] = proxy
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_client_certificate
func (client *HtmlToPdfClient) SetClientCertificate(certificate string) *HtmlToPdfClient {
    client.files["client_certificate"] = certificate
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_client_certificate_password
func (client *HtmlToPdfClient) SetClientCertificatePassword(password string) *HtmlToPdfClient {
    client.fields["client_certificate_password"] = password
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_layout_dpi
func (client *HtmlToPdfClient) SetLayoutDpi(dpi int) *HtmlToPdfClient {
    client.fields["layout_dpi"] = strconv.Itoa(dpi)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_content_area_x
func (client *HtmlToPdfClient) SetContentAreaX(x string) *HtmlToPdfClient {
    client.fields["content_area_x"] = x
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_content_area_y
func (client *HtmlToPdfClient) SetContentAreaY(y string) *HtmlToPdfClient {
    client.fields["content_area_y"] = y
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_content_area_width
func (client *HtmlToPdfClient) SetContentAreaWidth(width string) *HtmlToPdfClient {
    client.fields["content_area_width"] = width
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_content_area_height
func (client *HtmlToPdfClient) SetContentAreaHeight(height string) *HtmlToPdfClient {
    client.fields["content_area_height"] = height
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_content_area
func (client *HtmlToPdfClient) SetContentArea(x string, y string, width string, height string) *HtmlToPdfClient {
    client.SetContentAreaX(x)
    client.SetContentAreaY(y)
    client.SetContentAreaWidth(width)
    client.SetContentAreaHeight(height)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_contents_matrix
func (client *HtmlToPdfClient) SetContentsMatrix(matrix string) *HtmlToPdfClient {
    client.fields["contents_matrix"] = matrix
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_header_matrix
func (client *HtmlToPdfClient) SetHeaderMatrix(matrix string) *HtmlToPdfClient {
    client.fields["header_matrix"] = matrix
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_footer_matrix
func (client *HtmlToPdfClient) SetFooterMatrix(matrix string) *HtmlToPdfClient {
    client.fields["footer_matrix"] = matrix
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_disable_page_height_optimization
func (client *HtmlToPdfClient) SetDisablePageHeightOptimization(value bool) *HtmlToPdfClient {
    client.fields["disable_page_height_optimization"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_main_document_css_annotation
func (client *HtmlToPdfClient) SetMainDocumentCssAnnotation(value bool) *HtmlToPdfClient {
    client.fields["main_document_css_annotation"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_header_footer_css_annotation
func (client *HtmlToPdfClient) SetHeaderFooterCssAnnotation(value bool) *HtmlToPdfClient {
    client.fields["header_footer_css_annotation"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_max_loading_time
func (client *HtmlToPdfClient) SetMaxLoadingTime(maxTime int) *HtmlToPdfClient {
    client.fields["max_loading_time"] = strconv.Itoa(maxTime)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_conversion_config
func (client *HtmlToPdfClient) SetConversionConfig(jsonString string) *HtmlToPdfClient {
    client.fields["conversion_config"] = jsonString
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_conversion_config_file
func (client *HtmlToPdfClient) SetConversionConfigFile(filepath string) *HtmlToPdfClient {
    client.files["conversion_config_file"] = filepath
    return client
}


func (client *HtmlToPdfClient) SetSubprocessReferrer(referrer string) *HtmlToPdfClient {
    client.fields["subprocess_referrer"] = referrer
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_converter_user_agent
func (client *HtmlToPdfClient) SetConverterUserAgent(agent string) *HtmlToPdfClient {
    client.fields["converter_user_agent"] = agent
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_converter_version
func (client *HtmlToPdfClient) SetConverterVersion(version string) *HtmlToPdfClient {
    client.helper.setConverterVersion(version)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_use_http
func (client *HtmlToPdfClient) SetUseHttp(value bool) *HtmlToPdfClient {
    client.helper.setUseHttp(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_client_user_agent
func (client *HtmlToPdfClient) SetClientUserAgent(agent string) *HtmlToPdfClient {
    client.helper.setUserAgent(agent)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_user_agent
func (client *HtmlToPdfClient) SetUserAgent(agent string) *HtmlToPdfClient {
    client.helper.setUserAgent(agent)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_proxy
func (client *HtmlToPdfClient) SetProxy(host string, port int, userName string, password string) *HtmlToPdfClient {
    client.helper.setProxy(host, port, userName, password)
    return client
}

// See https://pdfcrowd.com/api/html-to-pdf-go/ref/#set_retry_count
func (client *HtmlToPdfClient) SetRetryCount(count int) *HtmlToPdfClient {
    client.helper.setRetryCount(count)
    return client
}

// Conversion from HTML to image.
//
// See https://pdfcrowd.com/api/html-to-image-go/
type HtmlToImageClient struct {
    helper connectionHelper
    fields map[string]string
    files map[string]string
    rawData map[string][]byte
    fileId int
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#NewHtmlToImageClient
func NewHtmlToImageClient(userName string, apiKey string) HtmlToImageClient {
    helper := newConnectionHelper(userName, apiKey)
    fields := map[string]string{
        "input_format": "html",
        "output_format": "png",
    }
    return HtmlToImageClient{ helper, fields, make(map[string]string), make(map[string][]byte), 1}
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_output_format
func (client *HtmlToImageClient) SetOutputFormat(outputFormat string) *HtmlToImageClient {
    client.fields["output_format"] = outputFormat
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#convert_url
func (client *HtmlToImageClient) ConvertUrl(url string) ([]byte, error) {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return nil, NewError(createInvalidValueMessage(url, "ConvertUrl", "html-to-image", "Supported protocols are http:// and https://.", "convert_url"), 470)
    }
    
    client.fields["url"] = url
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#convert_url_to_stream
func (client *HtmlToImageClient) ConvertUrlToStream(url string, outStream io.Writer) error {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return NewError(createInvalidValueMessage(url, "ConvertUrlToStream::url", "html-to-image", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470)
    }
    
    client.fields["url"] = url
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#convert_url_to_file
func (client *HtmlToImageClient) ConvertUrlToFile(url string, filePath string) error {
    if len(filePath) == 0 {
        return NewError(createInvalidValueMessage(filePath, "ConvertUrlToFile::file_path", "html-to-image", "The string must not be empty.", "convert_url_to_file"), 470)
    }
    
    outputFile, err := os.Create(filePath)
    if err != nil {
        return err
    }
    err = client.ConvertUrlToStream(url, outputFile)
    outputFile.Close()
    if err != nil {
        os.Remove(filePath)
        return err
    }
    return nil
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#convert_file
func (client *HtmlToImageClient) ConvertFile(file string) ([]byte, error) {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return nil, NewError(createInvalidValueMessage(file, "ConvertFile", "html-to-image", "The file must exist and not be empty.", "convert_file"), 470)
    }
    
    client.files["file"] = file
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#convert_file_to_stream
func (client *HtmlToImageClient) ConvertFileToStream(file string, outStream io.Writer) error {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return NewError(createInvalidValueMessage(file, "ConvertFileToStream::file", "html-to-image", "The file must exist and not be empty.", "convert_file_to_stream"), 470)
    }
    
    client.files["file"] = file
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#convert_file_to_file
func (client *HtmlToImageClient) ConvertFileToFile(file string, filePath string) error {
    if len(filePath) == 0 {
        return NewError(createInvalidValueMessage(filePath, "ConvertFileToFile::file_path", "html-to-image", "The string must not be empty.", "convert_file_to_file"), 470)
    }
    
    outputFile, err := os.Create(filePath)
    if err != nil {
        return err
    }
    err = client.ConvertFileToStream(file, outputFile)
    outputFile.Close()
    if err != nil {
        os.Remove(filePath)
        return err
    }
    return nil
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#convert_string
func (client *HtmlToImageClient) ConvertString(text string) ([]byte, error) {
    if len(text) == 0 {
        return nil, NewError(createInvalidValueMessage(text, "ConvertString", "html-to-image", "The string must not be empty.", "convert_string"), 470)
    }
    
    client.fields["text"] = text
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#convert_string_to_stream
func (client *HtmlToImageClient) ConvertStringToStream(text string, outStream io.Writer) error {
    if len(text) == 0 {
        return NewError(createInvalidValueMessage(text, "ConvertStringToStream::text", "html-to-image", "The string must not be empty.", "convert_string_to_stream"), 470)
    }
    
    client.fields["text"] = text
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#convert_string_to_file
func (client *HtmlToImageClient) ConvertStringToFile(text string, filePath string) error {
    if len(filePath) == 0 {
        return NewError(createInvalidValueMessage(filePath, "ConvertStringToFile::file_path", "html-to-image", "The string must not be empty.", "convert_string_to_file"), 470)
    }
    
    outputFile, err := os.Create(filePath)
    if err != nil {
        return err
    }
    err = client.ConvertStringToStream(text, outputFile)
    outputFile.Close()
    if err != nil {
        os.Remove(filePath)
        return err
    }
    return nil
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#convert_stream
func (client *HtmlToImageClient) ConvertStream(inStream io.Reader) ([]byte, error) {
    data, errRead := ioutil.ReadAll(inStream)
    if errRead != nil {
        return nil, errRead
    }

    client.rawData["stream"] = data
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#convert_stream_to_stream
func (client *HtmlToImageClient) ConvertStreamToStream(inStream io.Reader, outStream io.Writer) error {
    data, errRead := ioutil.ReadAll(inStream)
    if errRead != nil {
        return errRead
    }

    client.rawData["stream"] = data
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#convert_stream_to_file
func (client *HtmlToImageClient) ConvertStreamToFile(inStream io.Reader, filePath string) error {
    if len(filePath) == 0 {
        return NewError(createInvalidValueMessage(filePath, "ConvertStreamToFile::file_path", "html-to-image", "The string must not be empty.", "convert_stream_to_file"), 470)
    }
    
    outputFile, err := os.Create(filePath)
    if err != nil {
        return err
    }
    err = client.ConvertStreamToStream(inStream, outputFile)
    outputFile.Close()
    if err != nil {
        os.Remove(filePath)
        return err
    }
    return nil
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_zip_main_filename
func (client *HtmlToImageClient) SetZipMainFilename(filename string) *HtmlToImageClient {
    client.fields["zip_main_filename"] = filename
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_screenshot_width
func (client *HtmlToImageClient) SetScreenshotWidth(width int) *HtmlToImageClient {
    client.fields["screenshot_width"] = strconv.Itoa(width)
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_screenshot_height
func (client *HtmlToImageClient) SetScreenshotHeight(height int) *HtmlToImageClient {
    client.fields["screenshot_height"] = strconv.Itoa(height)
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_scale_factor
func (client *HtmlToImageClient) SetScaleFactor(factor int) *HtmlToImageClient {
    client.fields["scale_factor"] = strconv.Itoa(factor)
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_background_color
func (client *HtmlToImageClient) SetBackgroundColor(color string) *HtmlToImageClient {
    client.fields["background_color"] = color
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_use_print_media
func (client *HtmlToImageClient) SetUsePrintMedia(value bool) *HtmlToImageClient {
    client.fields["use_print_media"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_no_background
func (client *HtmlToImageClient) SetNoBackground(value bool) *HtmlToImageClient {
    client.fields["no_background"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_disable_javascript
func (client *HtmlToImageClient) SetDisableJavascript(value bool) *HtmlToImageClient {
    client.fields["disable_javascript"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_disable_image_loading
func (client *HtmlToImageClient) SetDisableImageLoading(value bool) *HtmlToImageClient {
    client.fields["disable_image_loading"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_disable_remote_fonts
func (client *HtmlToImageClient) SetDisableRemoteFonts(value bool) *HtmlToImageClient {
    client.fields["disable_remote_fonts"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_use_mobile_user_agent
func (client *HtmlToImageClient) SetUseMobileUserAgent(value bool) *HtmlToImageClient {
    client.fields["use_mobile_user_agent"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_load_iframes
func (client *HtmlToImageClient) SetLoadIframes(iframes string) *HtmlToImageClient {
    client.fields["load_iframes"] = iframes
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_block_ads
func (client *HtmlToImageClient) SetBlockAds(value bool) *HtmlToImageClient {
    client.fields["block_ads"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_default_encoding
func (client *HtmlToImageClient) SetDefaultEncoding(encoding string) *HtmlToImageClient {
    client.fields["default_encoding"] = encoding
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_locale
func (client *HtmlToImageClient) SetLocale(locale string) *HtmlToImageClient {
    client.fields["locale"] = locale
    return client
}


func (client *HtmlToImageClient) SetHttpAuthUserName(userName string) *HtmlToImageClient {
    client.fields["http_auth_user_name"] = userName
    return client
}


func (client *HtmlToImageClient) SetHttpAuthPassword(password string) *HtmlToImageClient {
    client.fields["http_auth_password"] = password
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_http_auth
func (client *HtmlToImageClient) SetHttpAuth(userName string, password string) *HtmlToImageClient {
    client.SetHttpAuthUserName(userName)
    client.SetHttpAuthPassword(password)
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_cookies
func (client *HtmlToImageClient) SetCookies(cookies string) *HtmlToImageClient {
    client.fields["cookies"] = cookies
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_verify_ssl_certificates
func (client *HtmlToImageClient) SetVerifySslCertificates(value bool) *HtmlToImageClient {
    client.fields["verify_ssl_certificates"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_fail_on_main_url_error
func (client *HtmlToImageClient) SetFailOnMainUrlError(failOnError bool) *HtmlToImageClient {
    client.fields["fail_on_main_url_error"] = strconv.FormatBool(failOnError)
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_fail_on_any_url_error
func (client *HtmlToImageClient) SetFailOnAnyUrlError(failOnError bool) *HtmlToImageClient {
    client.fields["fail_on_any_url_error"] = strconv.FormatBool(failOnError)
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_no_xpdfcrowd_header
func (client *HtmlToImageClient) SetNoXpdfcrowdHeader(value bool) *HtmlToImageClient {
    client.fields["no_xpdfcrowd_header"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_custom_css
func (client *HtmlToImageClient) SetCustomCss(css string) *HtmlToImageClient {
    client.fields["custom_css"] = css
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_custom_javascript
func (client *HtmlToImageClient) SetCustomJavascript(javascript string) *HtmlToImageClient {
    client.fields["custom_javascript"] = javascript
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_on_load_javascript
func (client *HtmlToImageClient) SetOnLoadJavascript(javascript string) *HtmlToImageClient {
    client.fields["on_load_javascript"] = javascript
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_custom_http_header
func (client *HtmlToImageClient) SetCustomHttpHeader(header string) *HtmlToImageClient {
    client.fields["custom_http_header"] = header
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_javascript_delay
func (client *HtmlToImageClient) SetJavascriptDelay(delay int) *HtmlToImageClient {
    client.fields["javascript_delay"] = strconv.Itoa(delay)
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_element_to_convert
func (client *HtmlToImageClient) SetElementToConvert(selectors string) *HtmlToImageClient {
    client.fields["element_to_convert"] = selectors
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_element_to_convert_mode
func (client *HtmlToImageClient) SetElementToConvertMode(mode string) *HtmlToImageClient {
    client.fields["element_to_convert_mode"] = mode
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_wait_for_element
func (client *HtmlToImageClient) SetWaitForElement(selectors string) *HtmlToImageClient {
    client.fields["wait_for_element"] = selectors
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_auto_detect_element_to_convert
func (client *HtmlToImageClient) SetAutoDetectElementToConvert(value bool) *HtmlToImageClient {
    client.fields["auto_detect_element_to_convert"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_readability_enhancements
func (client *HtmlToImageClient) SetReadabilityEnhancements(enhancements string) *HtmlToImageClient {
    client.fields["readability_enhancements"] = enhancements
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_data_string
func (client *HtmlToImageClient) SetDataString(dataString string) *HtmlToImageClient {
    client.fields["data_string"] = dataString
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_data_file
func (client *HtmlToImageClient) SetDataFile(dataFile string) *HtmlToImageClient {
    client.files["data_file"] = dataFile
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_data_format
func (client *HtmlToImageClient) SetDataFormat(dataFormat string) *HtmlToImageClient {
    client.fields["data_format"] = dataFormat
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_data_encoding
func (client *HtmlToImageClient) SetDataEncoding(encoding string) *HtmlToImageClient {
    client.fields["data_encoding"] = encoding
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_data_ignore_undefined
func (client *HtmlToImageClient) SetDataIgnoreUndefined(value bool) *HtmlToImageClient {
    client.fields["data_ignore_undefined"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_data_auto_escape
func (client *HtmlToImageClient) SetDataAutoEscape(value bool) *HtmlToImageClient {
    client.fields["data_auto_escape"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_data_trim_blocks
func (client *HtmlToImageClient) SetDataTrimBlocks(value bool) *HtmlToImageClient {
    client.fields["data_trim_blocks"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_data_options
func (client *HtmlToImageClient) SetDataOptions(options string) *HtmlToImageClient {
    client.fields["data_options"] = options
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_debug_log
func (client *HtmlToImageClient) SetDebugLog(value bool) *HtmlToImageClient {
    client.fields["debug_log"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#get_debug_log_url
func (client *HtmlToImageClient) GetDebugLogUrl() string {
    return client.helper.getDebugLogUrl()
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#get_remaining_credit_count
func (client *HtmlToImageClient) GetRemainingCreditCount() int {
    return client.helper.getRemainingCreditCount()
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#get_consumed_credit_count
func (client *HtmlToImageClient) GetConsumedCreditCount() int {
    return client.helper.getConsumedCreditCount()
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#get_job_id
func (client *HtmlToImageClient) GetJobId() string {
    return client.helper.getJobId()
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#get_output_size
func (client *HtmlToImageClient) GetOutputSize() int {
    return client.helper.getOutputSize()
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#get_version
func (client *HtmlToImageClient) GetVersion() string {
    return fmt.Sprintf("client %s, API v2, converter %s", CLIENT_VERSION, client.helper.getConverterVersion())
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_tag
func (client *HtmlToImageClient) SetTag(tag string) *HtmlToImageClient {
    client.fields["tag"] = tag
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_http_proxy
func (client *HtmlToImageClient) SetHttpProxy(proxy string) *HtmlToImageClient {
    client.fields["http_proxy"] = proxy
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_https_proxy
func (client *HtmlToImageClient) SetHttpsProxy(proxy string) *HtmlToImageClient {
    client.fields["https_proxy"] = proxy
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_client_certificate
func (client *HtmlToImageClient) SetClientCertificate(certificate string) *HtmlToImageClient {
    client.files["client_certificate"] = certificate
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_client_certificate_password
func (client *HtmlToImageClient) SetClientCertificatePassword(password string) *HtmlToImageClient {
    client.fields["client_certificate_password"] = password
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_max_loading_time
func (client *HtmlToImageClient) SetMaxLoadingTime(maxTime int) *HtmlToImageClient {
    client.fields["max_loading_time"] = strconv.Itoa(maxTime)
    return client
}


func (client *HtmlToImageClient) SetSubprocessReferrer(referrer string) *HtmlToImageClient {
    client.fields["subprocess_referrer"] = referrer
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_converter_user_agent
func (client *HtmlToImageClient) SetConverterUserAgent(agent string) *HtmlToImageClient {
    client.fields["converter_user_agent"] = agent
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_converter_version
func (client *HtmlToImageClient) SetConverterVersion(version string) *HtmlToImageClient {
    client.helper.setConverterVersion(version)
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_use_http
func (client *HtmlToImageClient) SetUseHttp(value bool) *HtmlToImageClient {
    client.helper.setUseHttp(value)
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_client_user_agent
func (client *HtmlToImageClient) SetClientUserAgent(agent string) *HtmlToImageClient {
    client.helper.setUserAgent(agent)
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_user_agent
func (client *HtmlToImageClient) SetUserAgent(agent string) *HtmlToImageClient {
    client.helper.setUserAgent(agent)
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_proxy
func (client *HtmlToImageClient) SetProxy(host string, port int, userName string, password string) *HtmlToImageClient {
    client.helper.setProxy(host, port, userName, password)
    return client
}

// See https://pdfcrowd.com/api/html-to-image-go/ref/#set_retry_count
func (client *HtmlToImageClient) SetRetryCount(count int) *HtmlToImageClient {
    client.helper.setRetryCount(count)
    return client
}

// Conversion from one image format to another image format.
//
// See https://pdfcrowd.com/api/image-to-image-go/
type ImageToImageClient struct {
    helper connectionHelper
    fields map[string]string
    files map[string]string
    rawData map[string][]byte
    fileId int
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#NewImageToImageClient
func NewImageToImageClient(userName string, apiKey string) ImageToImageClient {
    helper := newConnectionHelper(userName, apiKey)
    fields := map[string]string{
        "input_format": "image",
        "output_format": "png",
    }
    return ImageToImageClient{ helper, fields, make(map[string]string), make(map[string][]byte), 1}
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#convert_url
func (client *ImageToImageClient) ConvertUrl(url string) ([]byte, error) {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return nil, NewError(createInvalidValueMessage(url, "ConvertUrl", "image-to-image", "Supported protocols are http:// and https://.", "convert_url"), 470)
    }
    
    client.fields["url"] = url
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#convert_url_to_stream
func (client *ImageToImageClient) ConvertUrlToStream(url string, outStream io.Writer) error {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return NewError(createInvalidValueMessage(url, "ConvertUrlToStream::url", "image-to-image", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470)
    }
    
    client.fields["url"] = url
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#convert_url_to_file
func (client *ImageToImageClient) ConvertUrlToFile(url string, filePath string) error {
    if len(filePath) == 0 {
        return NewError(createInvalidValueMessage(filePath, "ConvertUrlToFile::file_path", "image-to-image", "The string must not be empty.", "convert_url_to_file"), 470)
    }
    
    outputFile, err := os.Create(filePath)
    if err != nil {
        return err
    }
    err = client.ConvertUrlToStream(url, outputFile)
    outputFile.Close()
    if err != nil {
        os.Remove(filePath)
        return err
    }
    return nil
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#convert_file
func (client *ImageToImageClient) ConvertFile(file string) ([]byte, error) {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return nil, NewError(createInvalidValueMessage(file, "ConvertFile", "image-to-image", "The file must exist and not be empty.", "convert_file"), 470)
    }
    
    client.files["file"] = file
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#convert_file_to_stream
func (client *ImageToImageClient) ConvertFileToStream(file string, outStream io.Writer) error {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return NewError(createInvalidValueMessage(file, "ConvertFileToStream::file", "image-to-image", "The file must exist and not be empty.", "convert_file_to_stream"), 470)
    }
    
    client.files["file"] = file
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#convert_file_to_file
func (client *ImageToImageClient) ConvertFileToFile(file string, filePath string) error {
    if len(filePath) == 0 {
        return NewError(createInvalidValueMessage(filePath, "ConvertFileToFile::file_path", "image-to-image", "The string must not be empty.", "convert_file_to_file"), 470)
    }
    
    outputFile, err := os.Create(filePath)
    if err != nil {
        return err
    }
    err = client.ConvertFileToStream(file, outputFile)
    outputFile.Close()
    if err != nil {
        os.Remove(filePath)
        return err
    }
    return nil
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#convert_raw_data
func (client *ImageToImageClient) ConvertRawData(data []byte) ([]byte, error) {
    client.rawData["file"] = data
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#convert_raw_data_to_stream
func (client *ImageToImageClient) ConvertRawDataToStream(data []byte, outStream io.Writer) error {
    client.rawData["file"] = data
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#convert_raw_data_to_file
func (client *ImageToImageClient) ConvertRawDataToFile(data []byte, filePath string) error {
    if len(filePath) == 0 {
        return NewError(createInvalidValueMessage(filePath, "ConvertRawDataToFile::file_path", "image-to-image", "The string must not be empty.", "convert_raw_data_to_file"), 470)
    }
    
    outputFile, err := os.Create(filePath)
    if err != nil {
        return err
    }
    err = client.ConvertRawDataToStream(data, outputFile)
    outputFile.Close()
    if err != nil {
        os.Remove(filePath)
        return err
    }
    return nil
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#convert_stream
func (client *ImageToImageClient) ConvertStream(inStream io.Reader) ([]byte, error) {
    data, errRead := ioutil.ReadAll(inStream)
    if errRead != nil {
        return nil, errRead
    }

    client.rawData["stream"] = data
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#convert_stream_to_stream
func (client *ImageToImageClient) ConvertStreamToStream(inStream io.Reader, outStream io.Writer) error {
    data, errRead := ioutil.ReadAll(inStream)
    if errRead != nil {
        return errRead
    }

    client.rawData["stream"] = data
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#convert_stream_to_file
func (client *ImageToImageClient) ConvertStreamToFile(inStream io.Reader, filePath string) error {
    if len(filePath) == 0 {
        return NewError(createInvalidValueMessage(filePath, "ConvertStreamToFile::file_path", "image-to-image", "The string must not be empty.", "convert_stream_to_file"), 470)
    }
    
    outputFile, err := os.Create(filePath)
    if err != nil {
        return err
    }
    err = client.ConvertStreamToStream(inStream, outputFile)
    outputFile.Close()
    if err != nil {
        os.Remove(filePath)
        return err
    }
    return nil
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_output_format
func (client *ImageToImageClient) SetOutputFormat(outputFormat string) *ImageToImageClient {
    client.fields["output_format"] = outputFormat
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_resize
func (client *ImageToImageClient) SetResize(resize string) *ImageToImageClient {
    client.fields["resize"] = resize
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_rotate
func (client *ImageToImageClient) SetRotate(rotate string) *ImageToImageClient {
    client.fields["rotate"] = rotate
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_crop_area_x
func (client *ImageToImageClient) SetCropAreaX(x string) *ImageToImageClient {
    client.fields["crop_area_x"] = x
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_crop_area_y
func (client *ImageToImageClient) SetCropAreaY(y string) *ImageToImageClient {
    client.fields["crop_area_y"] = y
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_crop_area_width
func (client *ImageToImageClient) SetCropAreaWidth(width string) *ImageToImageClient {
    client.fields["crop_area_width"] = width
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_crop_area_height
func (client *ImageToImageClient) SetCropAreaHeight(height string) *ImageToImageClient {
    client.fields["crop_area_height"] = height
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_crop_area
func (client *ImageToImageClient) SetCropArea(x string, y string, width string, height string) *ImageToImageClient {
    client.SetCropAreaX(x)
    client.SetCropAreaY(y)
    client.SetCropAreaWidth(width)
    client.SetCropAreaHeight(height)
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_remove_borders
func (client *ImageToImageClient) SetRemoveBorders(value bool) *ImageToImageClient {
    client.fields["remove_borders"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_canvas_size
func (client *ImageToImageClient) SetCanvasSize(size string) *ImageToImageClient {
    client.fields["canvas_size"] = size
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_canvas_width
func (client *ImageToImageClient) SetCanvasWidth(width string) *ImageToImageClient {
    client.fields["canvas_width"] = width
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_canvas_height
func (client *ImageToImageClient) SetCanvasHeight(height string) *ImageToImageClient {
    client.fields["canvas_height"] = height
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_canvas_dimensions
func (client *ImageToImageClient) SetCanvasDimensions(width string, height string) *ImageToImageClient {
    client.SetCanvasWidth(width)
    client.SetCanvasHeight(height)
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_orientation
func (client *ImageToImageClient) SetOrientation(orientation string) *ImageToImageClient {
    client.fields["orientation"] = orientation
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_position
func (client *ImageToImageClient) SetPosition(position string) *ImageToImageClient {
    client.fields["position"] = position
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_print_canvas_mode
func (client *ImageToImageClient) SetPrintCanvasMode(mode string) *ImageToImageClient {
    client.fields["print_canvas_mode"] = mode
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_margin_top
func (client *ImageToImageClient) SetMarginTop(top string) *ImageToImageClient {
    client.fields["margin_top"] = top
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_margin_right
func (client *ImageToImageClient) SetMarginRight(right string) *ImageToImageClient {
    client.fields["margin_right"] = right
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_margin_bottom
func (client *ImageToImageClient) SetMarginBottom(bottom string) *ImageToImageClient {
    client.fields["margin_bottom"] = bottom
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_margin_left
func (client *ImageToImageClient) SetMarginLeft(left string) *ImageToImageClient {
    client.fields["margin_left"] = left
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_margins
func (client *ImageToImageClient) SetMargins(top string, right string, bottom string, left string) *ImageToImageClient {
    client.SetMarginTop(top)
    client.SetMarginRight(right)
    client.SetMarginBottom(bottom)
    client.SetMarginLeft(left)
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_canvas_background_color
func (client *ImageToImageClient) SetCanvasBackgroundColor(color string) *ImageToImageClient {
    client.fields["canvas_background_color"] = color
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_dpi
func (client *ImageToImageClient) SetDpi(dpi int) *ImageToImageClient {
    client.fields["dpi"] = strconv.Itoa(dpi)
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_debug_log
func (client *ImageToImageClient) SetDebugLog(value bool) *ImageToImageClient {
    client.fields["debug_log"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#get_debug_log_url
func (client *ImageToImageClient) GetDebugLogUrl() string {
    return client.helper.getDebugLogUrl()
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#get_remaining_credit_count
func (client *ImageToImageClient) GetRemainingCreditCount() int {
    return client.helper.getRemainingCreditCount()
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#get_consumed_credit_count
func (client *ImageToImageClient) GetConsumedCreditCount() int {
    return client.helper.getConsumedCreditCount()
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#get_job_id
func (client *ImageToImageClient) GetJobId() string {
    return client.helper.getJobId()
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#get_output_size
func (client *ImageToImageClient) GetOutputSize() int {
    return client.helper.getOutputSize()
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#get_version
func (client *ImageToImageClient) GetVersion() string {
    return fmt.Sprintf("client %s, API v2, converter %s", CLIENT_VERSION, client.helper.getConverterVersion())
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_tag
func (client *ImageToImageClient) SetTag(tag string) *ImageToImageClient {
    client.fields["tag"] = tag
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_http_proxy
func (client *ImageToImageClient) SetHttpProxy(proxy string) *ImageToImageClient {
    client.fields["http_proxy"] = proxy
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_https_proxy
func (client *ImageToImageClient) SetHttpsProxy(proxy string) *ImageToImageClient {
    client.fields["https_proxy"] = proxy
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_converter_version
func (client *ImageToImageClient) SetConverterVersion(version string) *ImageToImageClient {
    client.helper.setConverterVersion(version)
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_use_http
func (client *ImageToImageClient) SetUseHttp(value bool) *ImageToImageClient {
    client.helper.setUseHttp(value)
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_client_user_agent
func (client *ImageToImageClient) SetClientUserAgent(agent string) *ImageToImageClient {
    client.helper.setUserAgent(agent)
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_user_agent
func (client *ImageToImageClient) SetUserAgent(agent string) *ImageToImageClient {
    client.helper.setUserAgent(agent)
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_proxy
func (client *ImageToImageClient) SetProxy(host string, port int, userName string, password string) *ImageToImageClient {
    client.helper.setProxy(host, port, userName, password)
    return client
}

// See https://pdfcrowd.com/api/image-to-image-go/ref/#set_retry_count
func (client *ImageToImageClient) SetRetryCount(count int) *ImageToImageClient {
    client.helper.setRetryCount(count)
    return client
}

// Conversion from PDF to PDF.
//
// See https://pdfcrowd.com/api/pdf-to-pdf-go/
type PdfToPdfClient struct {
    helper connectionHelper
    fields map[string]string
    files map[string]string
    rawData map[string][]byte
    fileId int
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#NewPdfToPdfClient
func NewPdfToPdfClient(userName string, apiKey string) PdfToPdfClient {
    helper := newConnectionHelper(userName, apiKey)
    fields := map[string]string{
        "input_format": "pdf",
        "output_format": "pdf",
    }
    return PdfToPdfClient{ helper, fields, make(map[string]string), make(map[string][]byte), 1}
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_action
func (client *PdfToPdfClient) SetAction(action string) *PdfToPdfClient {
    client.fields["action"] = action
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#convert
func (client *PdfToPdfClient) Convert() ([]byte, error) {
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#convert_to_stream
func (client *PdfToPdfClient) ConvertToStream(outStream io.Writer) error {
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#convert_to_file
func (client *PdfToPdfClient) ConvertToFile(filePath string) error {
    if len(filePath) == 0 {
        return NewError(createInvalidValueMessage(filePath, "ConvertToFile", "pdf-to-pdf", "The string must not be empty.", "convert_to_file"), 470)
    }
    
    outputFile, err := os.Create(filePath)
    if err != nil {
        return err
    }
    defer outputFile.Close()
    client.ConvertToStream(outputFile)
    return nil
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#add_pdf_file
func (client *PdfToPdfClient) AddPdfFile(filePath string) *PdfToPdfClient {
    client.files["f_" + strconv.Itoa(client.fileId)] = filePath
    client.fileId++
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#add_pdf_raw_data
func (client *PdfToPdfClient) AddPdfRawData(data []byte) *PdfToPdfClient {
    client.rawData["f_" + strconv.Itoa(client.fileId)] = data
    client.fileId++
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_input_pdf_password
func (client *PdfToPdfClient) SetInputPdfPassword(password string) *PdfToPdfClient {
    client.fields["input_pdf_password"] = password
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_page_range
func (client *PdfToPdfClient) SetPageRange(pages string) *PdfToPdfClient {
    client.fields["page_range"] = pages
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_page_watermark
func (client *PdfToPdfClient) SetPageWatermark(watermark string) *PdfToPdfClient {
    client.files["page_watermark"] = watermark
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_page_watermark_url
func (client *PdfToPdfClient) SetPageWatermarkUrl(url string) *PdfToPdfClient {
    client.fields["page_watermark_url"] = url
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_multipage_watermark
func (client *PdfToPdfClient) SetMultipageWatermark(watermark string) *PdfToPdfClient {
    client.files["multipage_watermark"] = watermark
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_multipage_watermark_url
func (client *PdfToPdfClient) SetMultipageWatermarkUrl(url string) *PdfToPdfClient {
    client.fields["multipage_watermark_url"] = url
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_page_background
func (client *PdfToPdfClient) SetPageBackground(background string) *PdfToPdfClient {
    client.files["page_background"] = background
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_page_background_url
func (client *PdfToPdfClient) SetPageBackgroundUrl(url string) *PdfToPdfClient {
    client.fields["page_background_url"] = url
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_multipage_background
func (client *PdfToPdfClient) SetMultipageBackground(background string) *PdfToPdfClient {
    client.files["multipage_background"] = background
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_multipage_background_url
func (client *PdfToPdfClient) SetMultipageBackgroundUrl(url string) *PdfToPdfClient {
    client.fields["multipage_background_url"] = url
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_linearize
func (client *PdfToPdfClient) SetLinearize(value bool) *PdfToPdfClient {
    client.fields["linearize"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_encrypt
func (client *PdfToPdfClient) SetEncrypt(value bool) *PdfToPdfClient {
    client.fields["encrypt"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_user_password
func (client *PdfToPdfClient) SetUserPassword(password string) *PdfToPdfClient {
    client.fields["user_password"] = password
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_owner_password
func (client *PdfToPdfClient) SetOwnerPassword(password string) *PdfToPdfClient {
    client.fields["owner_password"] = password
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_no_print
func (client *PdfToPdfClient) SetNoPrint(value bool) *PdfToPdfClient {
    client.fields["no_print"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_no_modify
func (client *PdfToPdfClient) SetNoModify(value bool) *PdfToPdfClient {
    client.fields["no_modify"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_no_copy
func (client *PdfToPdfClient) SetNoCopy(value bool) *PdfToPdfClient {
    client.fields["no_copy"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_title
func (client *PdfToPdfClient) SetTitle(title string) *PdfToPdfClient {
    client.fields["title"] = title
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_subject
func (client *PdfToPdfClient) SetSubject(subject string) *PdfToPdfClient {
    client.fields["subject"] = subject
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_author
func (client *PdfToPdfClient) SetAuthor(author string) *PdfToPdfClient {
    client.fields["author"] = author
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_keywords
func (client *PdfToPdfClient) SetKeywords(keywords string) *PdfToPdfClient {
    client.fields["keywords"] = keywords
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_use_metadata_from
func (client *PdfToPdfClient) SetUseMetadataFrom(index int) *PdfToPdfClient {
    client.fields["use_metadata_from"] = strconv.Itoa(index)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_page_layout
func (client *PdfToPdfClient) SetPageLayout(layout string) *PdfToPdfClient {
    client.fields["page_layout"] = layout
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_page_mode
func (client *PdfToPdfClient) SetPageMode(mode string) *PdfToPdfClient {
    client.fields["page_mode"] = mode
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_initial_zoom_type
func (client *PdfToPdfClient) SetInitialZoomType(zoomType string) *PdfToPdfClient {
    client.fields["initial_zoom_type"] = zoomType
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_initial_page
func (client *PdfToPdfClient) SetInitialPage(page int) *PdfToPdfClient {
    client.fields["initial_page"] = strconv.Itoa(page)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_initial_zoom
func (client *PdfToPdfClient) SetInitialZoom(zoom int) *PdfToPdfClient {
    client.fields["initial_zoom"] = strconv.Itoa(zoom)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_hide_toolbar
func (client *PdfToPdfClient) SetHideToolbar(value bool) *PdfToPdfClient {
    client.fields["hide_toolbar"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_hide_menubar
func (client *PdfToPdfClient) SetHideMenubar(value bool) *PdfToPdfClient {
    client.fields["hide_menubar"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_hide_window_ui
func (client *PdfToPdfClient) SetHideWindowUi(value bool) *PdfToPdfClient {
    client.fields["hide_window_ui"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_fit_window
func (client *PdfToPdfClient) SetFitWindow(value bool) *PdfToPdfClient {
    client.fields["fit_window"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_center_window
func (client *PdfToPdfClient) SetCenterWindow(value bool) *PdfToPdfClient {
    client.fields["center_window"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_display_title
func (client *PdfToPdfClient) SetDisplayTitle(value bool) *PdfToPdfClient {
    client.fields["display_title"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_right_to_left
func (client *PdfToPdfClient) SetRightToLeft(value bool) *PdfToPdfClient {
    client.fields["right_to_left"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_debug_log
func (client *PdfToPdfClient) SetDebugLog(value bool) *PdfToPdfClient {
    client.fields["debug_log"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#get_debug_log_url
func (client *PdfToPdfClient) GetDebugLogUrl() string {
    return client.helper.getDebugLogUrl()
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#get_remaining_credit_count
func (client *PdfToPdfClient) GetRemainingCreditCount() int {
    return client.helper.getRemainingCreditCount()
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#get_consumed_credit_count
func (client *PdfToPdfClient) GetConsumedCreditCount() int {
    return client.helper.getConsumedCreditCount()
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#get_job_id
func (client *PdfToPdfClient) GetJobId() string {
    return client.helper.getJobId()
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#get_page_count
func (client *PdfToPdfClient) GetPageCount() int {
    return client.helper.getPageCount()
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#get_output_size
func (client *PdfToPdfClient) GetOutputSize() int {
    return client.helper.getOutputSize()
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#get_version
func (client *PdfToPdfClient) GetVersion() string {
    return fmt.Sprintf("client %s, API v2, converter %s", CLIENT_VERSION, client.helper.getConverterVersion())
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_tag
func (client *PdfToPdfClient) SetTag(tag string) *PdfToPdfClient {
    client.fields["tag"] = tag
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_converter_version
func (client *PdfToPdfClient) SetConverterVersion(version string) *PdfToPdfClient {
    client.helper.setConverterVersion(version)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_use_http
func (client *PdfToPdfClient) SetUseHttp(value bool) *PdfToPdfClient {
    client.helper.setUseHttp(value)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_client_user_agent
func (client *PdfToPdfClient) SetClientUserAgent(agent string) *PdfToPdfClient {
    client.helper.setUserAgent(agent)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_user_agent
func (client *PdfToPdfClient) SetUserAgent(agent string) *PdfToPdfClient {
    client.helper.setUserAgent(agent)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_proxy
func (client *PdfToPdfClient) SetProxy(host string, port int, userName string, password string) *PdfToPdfClient {
    client.helper.setProxy(host, port, userName, password)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-pdf-go/ref/#set_retry_count
func (client *PdfToPdfClient) SetRetryCount(count int) *PdfToPdfClient {
    client.helper.setRetryCount(count)
    return client
}

// Conversion from an image to PDF.
//
// See https://pdfcrowd.com/api/image-to-pdf-go/
type ImageToPdfClient struct {
    helper connectionHelper
    fields map[string]string
    files map[string]string
    rawData map[string][]byte
    fileId int
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#NewImageToPdfClient
func NewImageToPdfClient(userName string, apiKey string) ImageToPdfClient {
    helper := newConnectionHelper(userName, apiKey)
    fields := map[string]string{
        "input_format": "image",
        "output_format": "pdf",
    }
    return ImageToPdfClient{ helper, fields, make(map[string]string), make(map[string][]byte), 1}
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#convert_url
func (client *ImageToPdfClient) ConvertUrl(url string) ([]byte, error) {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return nil, NewError(createInvalidValueMessage(url, "ConvertUrl", "image-to-pdf", "Supported protocols are http:// and https://.", "convert_url"), 470)
    }
    
    client.fields["url"] = url
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#convert_url_to_stream
func (client *ImageToPdfClient) ConvertUrlToStream(url string, outStream io.Writer) error {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return NewError(createInvalidValueMessage(url, "ConvertUrlToStream::url", "image-to-pdf", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470)
    }
    
    client.fields["url"] = url
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#convert_url_to_file
func (client *ImageToPdfClient) ConvertUrlToFile(url string, filePath string) error {
    if len(filePath) == 0 {
        return NewError(createInvalidValueMessage(filePath, "ConvertUrlToFile::file_path", "image-to-pdf", "The string must not be empty.", "convert_url_to_file"), 470)
    }
    
    outputFile, err := os.Create(filePath)
    if err != nil {
        return err
    }
    err = client.ConvertUrlToStream(url, outputFile)
    outputFile.Close()
    if err != nil {
        os.Remove(filePath)
        return err
    }
    return nil
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#convert_file
func (client *ImageToPdfClient) ConvertFile(file string) ([]byte, error) {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return nil, NewError(createInvalidValueMessage(file, "ConvertFile", "image-to-pdf", "The file must exist and not be empty.", "convert_file"), 470)
    }
    
    client.files["file"] = file
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#convert_file_to_stream
func (client *ImageToPdfClient) ConvertFileToStream(file string, outStream io.Writer) error {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return NewError(createInvalidValueMessage(file, "ConvertFileToStream::file", "image-to-pdf", "The file must exist and not be empty.", "convert_file_to_stream"), 470)
    }
    
    client.files["file"] = file
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#convert_file_to_file
func (client *ImageToPdfClient) ConvertFileToFile(file string, filePath string) error {
    if len(filePath) == 0 {
        return NewError(createInvalidValueMessage(filePath, "ConvertFileToFile::file_path", "image-to-pdf", "The string must not be empty.", "convert_file_to_file"), 470)
    }
    
    outputFile, err := os.Create(filePath)
    if err != nil {
        return err
    }
    err = client.ConvertFileToStream(file, outputFile)
    outputFile.Close()
    if err != nil {
        os.Remove(filePath)
        return err
    }
    return nil
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#convert_raw_data
func (client *ImageToPdfClient) ConvertRawData(data []byte) ([]byte, error) {
    client.rawData["file"] = data
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#convert_raw_data_to_stream
func (client *ImageToPdfClient) ConvertRawDataToStream(data []byte, outStream io.Writer) error {
    client.rawData["file"] = data
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#convert_raw_data_to_file
func (client *ImageToPdfClient) ConvertRawDataToFile(data []byte, filePath string) error {
    if len(filePath) == 0 {
        return NewError(createInvalidValueMessage(filePath, "ConvertRawDataToFile::file_path", "image-to-pdf", "The string must not be empty.", "convert_raw_data_to_file"), 470)
    }
    
    outputFile, err := os.Create(filePath)
    if err != nil {
        return err
    }
    err = client.ConvertRawDataToStream(data, outputFile)
    outputFile.Close()
    if err != nil {
        os.Remove(filePath)
        return err
    }
    return nil
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#convert_stream
func (client *ImageToPdfClient) ConvertStream(inStream io.Reader) ([]byte, error) {
    data, errRead := ioutil.ReadAll(inStream)
    if errRead != nil {
        return nil, errRead
    }

    client.rawData["stream"] = data
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#convert_stream_to_stream
func (client *ImageToPdfClient) ConvertStreamToStream(inStream io.Reader, outStream io.Writer) error {
    data, errRead := ioutil.ReadAll(inStream)
    if errRead != nil {
        return errRead
    }

    client.rawData["stream"] = data
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#convert_stream_to_file
func (client *ImageToPdfClient) ConvertStreamToFile(inStream io.Reader, filePath string) error {
    if len(filePath) == 0 {
        return NewError(createInvalidValueMessage(filePath, "ConvertStreamToFile::file_path", "image-to-pdf", "The string must not be empty.", "convert_stream_to_file"), 470)
    }
    
    outputFile, err := os.Create(filePath)
    if err != nil {
        return err
    }
    err = client.ConvertStreamToStream(inStream, outputFile)
    outputFile.Close()
    if err != nil {
        os.Remove(filePath)
        return err
    }
    return nil
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_resize
func (client *ImageToPdfClient) SetResize(resize string) *ImageToPdfClient {
    client.fields["resize"] = resize
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_rotate
func (client *ImageToPdfClient) SetRotate(rotate string) *ImageToPdfClient {
    client.fields["rotate"] = rotate
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_crop_area_x
func (client *ImageToPdfClient) SetCropAreaX(x string) *ImageToPdfClient {
    client.fields["crop_area_x"] = x
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_crop_area_y
func (client *ImageToPdfClient) SetCropAreaY(y string) *ImageToPdfClient {
    client.fields["crop_area_y"] = y
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_crop_area_width
func (client *ImageToPdfClient) SetCropAreaWidth(width string) *ImageToPdfClient {
    client.fields["crop_area_width"] = width
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_crop_area_height
func (client *ImageToPdfClient) SetCropAreaHeight(height string) *ImageToPdfClient {
    client.fields["crop_area_height"] = height
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_crop_area
func (client *ImageToPdfClient) SetCropArea(x string, y string, width string, height string) *ImageToPdfClient {
    client.SetCropAreaX(x)
    client.SetCropAreaY(y)
    client.SetCropAreaWidth(width)
    client.SetCropAreaHeight(height)
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_remove_borders
func (client *ImageToPdfClient) SetRemoveBorders(value bool) *ImageToPdfClient {
    client.fields["remove_borders"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_page_size
func (client *ImageToPdfClient) SetPageSize(size string) *ImageToPdfClient {
    client.fields["page_size"] = size
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_page_width
func (client *ImageToPdfClient) SetPageWidth(width string) *ImageToPdfClient {
    client.fields["page_width"] = width
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_page_height
func (client *ImageToPdfClient) SetPageHeight(height string) *ImageToPdfClient {
    client.fields["page_height"] = height
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_page_dimensions
func (client *ImageToPdfClient) SetPageDimensions(width string, height string) *ImageToPdfClient {
    client.SetPageWidth(width)
    client.SetPageHeight(height)
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_orientation
func (client *ImageToPdfClient) SetOrientation(orientation string) *ImageToPdfClient {
    client.fields["orientation"] = orientation
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_position
func (client *ImageToPdfClient) SetPosition(position string) *ImageToPdfClient {
    client.fields["position"] = position
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_print_page_mode
func (client *ImageToPdfClient) SetPrintPageMode(mode string) *ImageToPdfClient {
    client.fields["print_page_mode"] = mode
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_margin_top
func (client *ImageToPdfClient) SetMarginTop(top string) *ImageToPdfClient {
    client.fields["margin_top"] = top
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_margin_right
func (client *ImageToPdfClient) SetMarginRight(right string) *ImageToPdfClient {
    client.fields["margin_right"] = right
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_margin_bottom
func (client *ImageToPdfClient) SetMarginBottom(bottom string) *ImageToPdfClient {
    client.fields["margin_bottom"] = bottom
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_margin_left
func (client *ImageToPdfClient) SetMarginLeft(left string) *ImageToPdfClient {
    client.fields["margin_left"] = left
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_page_margins
func (client *ImageToPdfClient) SetPageMargins(top string, right string, bottom string, left string) *ImageToPdfClient {
    client.SetMarginTop(top)
    client.SetMarginRight(right)
    client.SetMarginBottom(bottom)
    client.SetMarginLeft(left)
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_page_background_color
func (client *ImageToPdfClient) SetPageBackgroundColor(color string) *ImageToPdfClient {
    client.fields["page_background_color"] = color
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_dpi
func (client *ImageToPdfClient) SetDpi(dpi int) *ImageToPdfClient {
    client.fields["dpi"] = strconv.Itoa(dpi)
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_page_watermark
func (client *ImageToPdfClient) SetPageWatermark(watermark string) *ImageToPdfClient {
    client.files["page_watermark"] = watermark
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_page_watermark_url
func (client *ImageToPdfClient) SetPageWatermarkUrl(url string) *ImageToPdfClient {
    client.fields["page_watermark_url"] = url
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_multipage_watermark
func (client *ImageToPdfClient) SetMultipageWatermark(watermark string) *ImageToPdfClient {
    client.files["multipage_watermark"] = watermark
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_multipage_watermark_url
func (client *ImageToPdfClient) SetMultipageWatermarkUrl(url string) *ImageToPdfClient {
    client.fields["multipage_watermark_url"] = url
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_page_background
func (client *ImageToPdfClient) SetPageBackground(background string) *ImageToPdfClient {
    client.files["page_background"] = background
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_page_background_url
func (client *ImageToPdfClient) SetPageBackgroundUrl(url string) *ImageToPdfClient {
    client.fields["page_background_url"] = url
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_multipage_background
func (client *ImageToPdfClient) SetMultipageBackground(background string) *ImageToPdfClient {
    client.files["multipage_background"] = background
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_multipage_background_url
func (client *ImageToPdfClient) SetMultipageBackgroundUrl(url string) *ImageToPdfClient {
    client.fields["multipage_background_url"] = url
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_linearize
func (client *ImageToPdfClient) SetLinearize(value bool) *ImageToPdfClient {
    client.fields["linearize"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_encrypt
func (client *ImageToPdfClient) SetEncrypt(value bool) *ImageToPdfClient {
    client.fields["encrypt"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_user_password
func (client *ImageToPdfClient) SetUserPassword(password string) *ImageToPdfClient {
    client.fields["user_password"] = password
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_owner_password
func (client *ImageToPdfClient) SetOwnerPassword(password string) *ImageToPdfClient {
    client.fields["owner_password"] = password
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_no_print
func (client *ImageToPdfClient) SetNoPrint(value bool) *ImageToPdfClient {
    client.fields["no_print"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_no_modify
func (client *ImageToPdfClient) SetNoModify(value bool) *ImageToPdfClient {
    client.fields["no_modify"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_no_copy
func (client *ImageToPdfClient) SetNoCopy(value bool) *ImageToPdfClient {
    client.fields["no_copy"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_title
func (client *ImageToPdfClient) SetTitle(title string) *ImageToPdfClient {
    client.fields["title"] = title
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_subject
func (client *ImageToPdfClient) SetSubject(subject string) *ImageToPdfClient {
    client.fields["subject"] = subject
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_author
func (client *ImageToPdfClient) SetAuthor(author string) *ImageToPdfClient {
    client.fields["author"] = author
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_keywords
func (client *ImageToPdfClient) SetKeywords(keywords string) *ImageToPdfClient {
    client.fields["keywords"] = keywords
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_page_layout
func (client *ImageToPdfClient) SetPageLayout(layout string) *ImageToPdfClient {
    client.fields["page_layout"] = layout
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_page_mode
func (client *ImageToPdfClient) SetPageMode(mode string) *ImageToPdfClient {
    client.fields["page_mode"] = mode
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_initial_zoom_type
func (client *ImageToPdfClient) SetInitialZoomType(zoomType string) *ImageToPdfClient {
    client.fields["initial_zoom_type"] = zoomType
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_initial_page
func (client *ImageToPdfClient) SetInitialPage(page int) *ImageToPdfClient {
    client.fields["initial_page"] = strconv.Itoa(page)
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_initial_zoom
func (client *ImageToPdfClient) SetInitialZoom(zoom int) *ImageToPdfClient {
    client.fields["initial_zoom"] = strconv.Itoa(zoom)
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_hide_toolbar
func (client *ImageToPdfClient) SetHideToolbar(value bool) *ImageToPdfClient {
    client.fields["hide_toolbar"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_hide_menubar
func (client *ImageToPdfClient) SetHideMenubar(value bool) *ImageToPdfClient {
    client.fields["hide_menubar"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_hide_window_ui
func (client *ImageToPdfClient) SetHideWindowUi(value bool) *ImageToPdfClient {
    client.fields["hide_window_ui"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_fit_window
func (client *ImageToPdfClient) SetFitWindow(value bool) *ImageToPdfClient {
    client.fields["fit_window"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_center_window
func (client *ImageToPdfClient) SetCenterWindow(value bool) *ImageToPdfClient {
    client.fields["center_window"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_display_title
func (client *ImageToPdfClient) SetDisplayTitle(value bool) *ImageToPdfClient {
    client.fields["display_title"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_debug_log
func (client *ImageToPdfClient) SetDebugLog(value bool) *ImageToPdfClient {
    client.fields["debug_log"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#get_debug_log_url
func (client *ImageToPdfClient) GetDebugLogUrl() string {
    return client.helper.getDebugLogUrl()
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#get_remaining_credit_count
func (client *ImageToPdfClient) GetRemainingCreditCount() int {
    return client.helper.getRemainingCreditCount()
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#get_consumed_credit_count
func (client *ImageToPdfClient) GetConsumedCreditCount() int {
    return client.helper.getConsumedCreditCount()
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#get_job_id
func (client *ImageToPdfClient) GetJobId() string {
    return client.helper.getJobId()
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#get_output_size
func (client *ImageToPdfClient) GetOutputSize() int {
    return client.helper.getOutputSize()
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#get_version
func (client *ImageToPdfClient) GetVersion() string {
    return fmt.Sprintf("client %s, API v2, converter %s", CLIENT_VERSION, client.helper.getConverterVersion())
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_tag
func (client *ImageToPdfClient) SetTag(tag string) *ImageToPdfClient {
    client.fields["tag"] = tag
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_http_proxy
func (client *ImageToPdfClient) SetHttpProxy(proxy string) *ImageToPdfClient {
    client.fields["http_proxy"] = proxy
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_https_proxy
func (client *ImageToPdfClient) SetHttpsProxy(proxy string) *ImageToPdfClient {
    client.fields["https_proxy"] = proxy
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_converter_version
func (client *ImageToPdfClient) SetConverterVersion(version string) *ImageToPdfClient {
    client.helper.setConverterVersion(version)
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_use_http
func (client *ImageToPdfClient) SetUseHttp(value bool) *ImageToPdfClient {
    client.helper.setUseHttp(value)
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_client_user_agent
func (client *ImageToPdfClient) SetClientUserAgent(agent string) *ImageToPdfClient {
    client.helper.setUserAgent(agent)
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_user_agent
func (client *ImageToPdfClient) SetUserAgent(agent string) *ImageToPdfClient {
    client.helper.setUserAgent(agent)
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_proxy
func (client *ImageToPdfClient) SetProxy(host string, port int, userName string, password string) *ImageToPdfClient {
    client.helper.setProxy(host, port, userName, password)
    return client
}

// See https://pdfcrowd.com/api/image-to-pdf-go/ref/#set_retry_count
func (client *ImageToPdfClient) SetRetryCount(count int) *ImageToPdfClient {
    client.helper.setRetryCount(count)
    return client
}

// Conversion from PDF to HTML.
//
// See https://pdfcrowd.com/api/pdf-to-html-go/
type PdfToHtmlClient struct {
    helper connectionHelper
    fields map[string]string
    files map[string]string
    rawData map[string][]byte
    fileId int
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#NewPdfToHtmlClient
func NewPdfToHtmlClient(userName string, apiKey string) PdfToHtmlClient {
    helper := newConnectionHelper(userName, apiKey)
    fields := map[string]string{
        "input_format": "pdf",
        "output_format": "html",
    }
    return PdfToHtmlClient{ helper, fields, make(map[string]string), make(map[string][]byte), 1}
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#convert_url
func (client *PdfToHtmlClient) ConvertUrl(url string) ([]byte, error) {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return nil, NewError(createInvalidValueMessage(url, "ConvertUrl", "pdf-to-html", "Supported protocols are http:// and https://.", "convert_url"), 470)
    }
    
    client.fields["url"] = url
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#convert_url_to_stream
func (client *PdfToHtmlClient) ConvertUrlToStream(url string, outStream io.Writer) error {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return NewError(createInvalidValueMessage(url, "ConvertUrlToStream::url", "pdf-to-html", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470)
    }
    
    client.fields["url"] = url
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#convert_url_to_file
func (client *PdfToHtmlClient) ConvertUrlToFile(url string, filePath string) error {
    if len(filePath) == 0 {
        return NewError(createInvalidValueMessage(filePath, "ConvertUrlToFile::file_path", "pdf-to-html", "The string must not be empty.", "convert_url_to_file"), 470)
    }
    
    if !client.isOutputTypeValid(filePath) {
        return NewError(createInvalidValueMessage(filePath, "ConvertUrlToFile::file_path", "pdf-to-html", "The converter generates an HTML or ZIP file. If ZIP file is generated, the file path must have a ZIP or zip extension.", "convert_url_to_file"), 470)
    }
    
    outputFile, err := os.Create(filePath)
    if err != nil {
        return err
    }
    err = client.ConvertUrlToStream(url, outputFile)
    outputFile.Close()
    if err != nil {
        os.Remove(filePath)
        return err
    }
    return nil
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#convert_file
func (client *PdfToHtmlClient) ConvertFile(file string) ([]byte, error) {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return nil, NewError(createInvalidValueMessage(file, "ConvertFile", "pdf-to-html", "The file must exist and not be empty.", "convert_file"), 470)
    }
    
    client.files["file"] = file
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#convert_file_to_stream
func (client *PdfToHtmlClient) ConvertFileToStream(file string, outStream io.Writer) error {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return NewError(createInvalidValueMessage(file, "ConvertFileToStream::file", "pdf-to-html", "The file must exist and not be empty.", "convert_file_to_stream"), 470)
    }
    
    client.files["file"] = file
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#convert_file_to_file
func (client *PdfToHtmlClient) ConvertFileToFile(file string, filePath string) error {
    if len(filePath) == 0 {
        return NewError(createInvalidValueMessage(filePath, "ConvertFileToFile::file_path", "pdf-to-html", "The string must not be empty.", "convert_file_to_file"), 470)
    }
    
    if !client.isOutputTypeValid(filePath) {
        return NewError(createInvalidValueMessage(filePath, "ConvertFileToFile::file_path", "pdf-to-html", "The converter generates an HTML or ZIP file. If ZIP file is generated, the file path must have a ZIP or zip extension.", "convert_file_to_file"), 470)
    }
    
    outputFile, err := os.Create(filePath)
    if err != nil {
        return err
    }
    err = client.ConvertFileToStream(file, outputFile)
    outputFile.Close()
    if err != nil {
        os.Remove(filePath)
        return err
    }
    return nil
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#convert_raw_data
func (client *PdfToHtmlClient) ConvertRawData(data []byte) ([]byte, error) {
    client.rawData["file"] = data
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#convert_raw_data_to_stream
func (client *PdfToHtmlClient) ConvertRawDataToStream(data []byte, outStream io.Writer) error {
    client.rawData["file"] = data
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#convert_raw_data_to_file
func (client *PdfToHtmlClient) ConvertRawDataToFile(data []byte, filePath string) error {
    if len(filePath) == 0 {
        return NewError(createInvalidValueMessage(filePath, "ConvertRawDataToFile::file_path", "pdf-to-html", "The string must not be empty.", "convert_raw_data_to_file"), 470)
    }
    
    if !client.isOutputTypeValid(filePath) {
        return NewError(createInvalidValueMessage(filePath, "ConvertRawDataToFile::file_path", "pdf-to-html", "The converter generates an HTML or ZIP file. If ZIP file is generated, the file path must have a ZIP or zip extension.", "convert_raw_data_to_file"), 470)
    }
    
    outputFile, err := os.Create(filePath)
    if err != nil {
        return err
    }
    err = client.ConvertRawDataToStream(data, outputFile)
    outputFile.Close()
    if err != nil {
        os.Remove(filePath)
        return err
    }
    return nil
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#convert_stream
func (client *PdfToHtmlClient) ConvertStream(inStream io.Reader) ([]byte, error) {
    data, errRead := ioutil.ReadAll(inStream)
    if errRead != nil {
        return nil, errRead
    }

    client.rawData["stream"] = data
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#convert_stream_to_stream
func (client *PdfToHtmlClient) ConvertStreamToStream(inStream io.Reader, outStream io.Writer) error {
    data, errRead := ioutil.ReadAll(inStream)
    if errRead != nil {
        return errRead
    }

    client.rawData["stream"] = data
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#convert_stream_to_file
func (client *PdfToHtmlClient) ConvertStreamToFile(inStream io.Reader, filePath string) error {
    if len(filePath) == 0 {
        return NewError(createInvalidValueMessage(filePath, "ConvertStreamToFile::file_path", "pdf-to-html", "The string must not be empty.", "convert_stream_to_file"), 470)
    }
    
    if !client.isOutputTypeValid(filePath) {
        return NewError(createInvalidValueMessage(filePath, "ConvertStreamToFile::file_path", "pdf-to-html", "The converter generates an HTML or ZIP file. If ZIP file is generated, the file path must have a ZIP or zip extension.", "convert_stream_to_file"), 470)
    }
    
    outputFile, err := os.Create(filePath)
    if err != nil {
        return err
    }
    err = client.ConvertStreamToStream(inStream, outputFile)
    outputFile.Close()
    if err != nil {
        os.Remove(filePath)
        return err
    }
    return nil
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#set_pdf_password
func (client *PdfToHtmlClient) SetPdfPassword(password string) *PdfToHtmlClient {
    client.fields["pdf_password"] = password
    return client
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#set_scale_factor
func (client *PdfToHtmlClient) SetScaleFactor(factor int) *PdfToHtmlClient {
    client.fields["scale_factor"] = strconv.Itoa(factor)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#set_print_page_range
func (client *PdfToHtmlClient) SetPrintPageRange(pages string) *PdfToHtmlClient {
    client.fields["print_page_range"] = pages
    return client
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#set_dpi
func (client *PdfToHtmlClient) SetDpi(dpi int) *PdfToHtmlClient {
    client.fields["dpi"] = strconv.Itoa(dpi)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#set_image_mode
func (client *PdfToHtmlClient) SetImageMode(mode string) *PdfToHtmlClient {
    client.fields["image_mode"] = mode
    return client
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#set_image_format
func (client *PdfToHtmlClient) SetImageFormat(imageFormat string) *PdfToHtmlClient {
    client.fields["image_format"] = imageFormat
    return client
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#set_css_mode
func (client *PdfToHtmlClient) SetCssMode(mode string) *PdfToHtmlClient {
    client.fields["css_mode"] = mode
    return client
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#set_font_mode
func (client *PdfToHtmlClient) SetFontMode(mode string) *PdfToHtmlClient {
    client.fields["font_mode"] = mode
    return client
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#set_type3_mode
func (client *PdfToHtmlClient) SetType3Mode(mode string) *PdfToHtmlClient {
    client.fields["type3_mode"] = mode
    return client
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#set_split_ligatures
func (client *PdfToHtmlClient) SetSplitLigatures(value bool) *PdfToHtmlClient {
    client.fields["split_ligatures"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#set_custom_css
func (client *PdfToHtmlClient) SetCustomCss(css string) *PdfToHtmlClient {
    client.fields["custom_css"] = css
    return client
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#set_html_namespace
func (client *PdfToHtmlClient) SetHtmlNamespace(prefix string) *PdfToHtmlClient {
    client.fields["html_namespace"] = prefix
    return client
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#is_zipped_output
func (client *PdfToHtmlClient) IsZippedOutput() bool {
    return client.fields["image_mode"] == "separate" || client.fields["css_mode"] == "separate" || client.fields["font_mode"] == "separate" || client.fields["force_zip"] == "true"
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#set_force_zip
func (client *PdfToHtmlClient) SetForceZip(value bool) *PdfToHtmlClient {
    client.fields["force_zip"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#set_title
func (client *PdfToHtmlClient) SetTitle(title string) *PdfToHtmlClient {
    client.fields["title"] = title
    return client
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#set_subject
func (client *PdfToHtmlClient) SetSubject(subject string) *PdfToHtmlClient {
    client.fields["subject"] = subject
    return client
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#set_author
func (client *PdfToHtmlClient) SetAuthor(author string) *PdfToHtmlClient {
    client.fields["author"] = author
    return client
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#set_keywords
func (client *PdfToHtmlClient) SetKeywords(keywords string) *PdfToHtmlClient {
    client.fields["keywords"] = keywords
    return client
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#set_debug_log
func (client *PdfToHtmlClient) SetDebugLog(value bool) *PdfToHtmlClient {
    client.fields["debug_log"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#get_debug_log_url
func (client *PdfToHtmlClient) GetDebugLogUrl() string {
    return client.helper.getDebugLogUrl()
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#get_remaining_credit_count
func (client *PdfToHtmlClient) GetRemainingCreditCount() int {
    return client.helper.getRemainingCreditCount()
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#get_consumed_credit_count
func (client *PdfToHtmlClient) GetConsumedCreditCount() int {
    return client.helper.getConsumedCreditCount()
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#get_job_id
func (client *PdfToHtmlClient) GetJobId() string {
    return client.helper.getJobId()
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#get_page_count
func (client *PdfToHtmlClient) GetPageCount() int {
    return client.helper.getPageCount()
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#get_output_size
func (client *PdfToHtmlClient) GetOutputSize() int {
    return client.helper.getOutputSize()
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#get_version
func (client *PdfToHtmlClient) GetVersion() string {
    return fmt.Sprintf("client %s, API v2, converter %s", CLIENT_VERSION, client.helper.getConverterVersion())
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#set_tag
func (client *PdfToHtmlClient) SetTag(tag string) *PdfToHtmlClient {
    client.fields["tag"] = tag
    return client
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#set_http_proxy
func (client *PdfToHtmlClient) SetHttpProxy(proxy string) *PdfToHtmlClient {
    client.fields["http_proxy"] = proxy
    return client
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#set_https_proxy
func (client *PdfToHtmlClient) SetHttpsProxy(proxy string) *PdfToHtmlClient {
    client.fields["https_proxy"] = proxy
    return client
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#set_converter_version
func (client *PdfToHtmlClient) SetConverterVersion(version string) *PdfToHtmlClient {
    client.helper.setConverterVersion(version)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#set_use_http
func (client *PdfToHtmlClient) SetUseHttp(value bool) *PdfToHtmlClient {
    client.helper.setUseHttp(value)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#set_client_user_agent
func (client *PdfToHtmlClient) SetClientUserAgent(agent string) *PdfToHtmlClient {
    client.helper.setUserAgent(agent)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#set_user_agent
func (client *PdfToHtmlClient) SetUserAgent(agent string) *PdfToHtmlClient {
    client.helper.setUserAgent(agent)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#set_proxy
func (client *PdfToHtmlClient) SetProxy(host string, port int, userName string, password string) *PdfToHtmlClient {
    client.helper.setProxy(host, port, userName, password)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-html-go/ref/#set_retry_count
func (client *PdfToHtmlClient) SetRetryCount(count int) *PdfToHtmlClient {
    client.helper.setRetryCount(count)
    return client
}

func (client *PdfToHtmlClient) isOutputTypeValid(file_path string) bool {
    extension := filepath.Ext(file_path)
    return (extension == ".zip") == client.IsZippedOutput()
}
// Conversion from PDF to text.
//
// See https://pdfcrowd.com/api/pdf-to-text-go/
type PdfToTextClient struct {
    helper connectionHelper
    fields map[string]string
    files map[string]string
    rawData map[string][]byte
    fileId int
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#NewPdfToTextClient
func NewPdfToTextClient(userName string, apiKey string) PdfToTextClient {
    helper := newConnectionHelper(userName, apiKey)
    fields := map[string]string{
        "input_format": "pdf",
        "output_format": "txt",
    }
    return PdfToTextClient{ helper, fields, make(map[string]string), make(map[string][]byte), 1}
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#convert_url
func (client *PdfToTextClient) ConvertUrl(url string) ([]byte, error) {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return nil, NewError(createInvalidValueMessage(url, "ConvertUrl", "pdf-to-text", "Supported protocols are http:// and https://.", "convert_url"), 470)
    }
    
    client.fields["url"] = url
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#convert_url_to_stream
func (client *PdfToTextClient) ConvertUrlToStream(url string, outStream io.Writer) error {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return NewError(createInvalidValueMessage(url, "ConvertUrlToStream::url", "pdf-to-text", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470)
    }
    
    client.fields["url"] = url
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#convert_url_to_file
func (client *PdfToTextClient) ConvertUrlToFile(url string, filePath string) error {
    if len(filePath) == 0 {
        return NewError(createInvalidValueMessage(filePath, "ConvertUrlToFile::file_path", "pdf-to-text", "The string must not be empty.", "convert_url_to_file"), 470)
    }
    
    outputFile, err := os.Create(filePath)
    if err != nil {
        return err
    }
    err = client.ConvertUrlToStream(url, outputFile)
    outputFile.Close()
    if err != nil {
        os.Remove(filePath)
        return err
    }
    return nil
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#convert_file
func (client *PdfToTextClient) ConvertFile(file string) ([]byte, error) {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return nil, NewError(createInvalidValueMessage(file, "ConvertFile", "pdf-to-text", "The file must exist and not be empty.", "convert_file"), 470)
    }
    
    client.files["file"] = file
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#convert_file_to_stream
func (client *PdfToTextClient) ConvertFileToStream(file string, outStream io.Writer) error {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return NewError(createInvalidValueMessage(file, "ConvertFileToStream::file", "pdf-to-text", "The file must exist and not be empty.", "convert_file_to_stream"), 470)
    }
    
    client.files["file"] = file
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#convert_file_to_file
func (client *PdfToTextClient) ConvertFileToFile(file string, filePath string) error {
    if len(filePath) == 0 {
        return NewError(createInvalidValueMessage(filePath, "ConvertFileToFile::file_path", "pdf-to-text", "The string must not be empty.", "convert_file_to_file"), 470)
    }
    
    outputFile, err := os.Create(filePath)
    if err != nil {
        return err
    }
    err = client.ConvertFileToStream(file, outputFile)
    outputFile.Close()
    if err != nil {
        os.Remove(filePath)
        return err
    }
    return nil
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#convert_raw_data
func (client *PdfToTextClient) ConvertRawData(data []byte) ([]byte, error) {
    client.rawData["file"] = data
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#convert_raw_data_to_stream
func (client *PdfToTextClient) ConvertRawDataToStream(data []byte, outStream io.Writer) error {
    client.rawData["file"] = data
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#convert_raw_data_to_file
func (client *PdfToTextClient) ConvertRawDataToFile(data []byte, filePath string) error {
    if len(filePath) == 0 {
        return NewError(createInvalidValueMessage(filePath, "ConvertRawDataToFile::file_path", "pdf-to-text", "The string must not be empty.", "convert_raw_data_to_file"), 470)
    }
    
    outputFile, err := os.Create(filePath)
    if err != nil {
        return err
    }
    err = client.ConvertRawDataToStream(data, outputFile)
    outputFile.Close()
    if err != nil {
        os.Remove(filePath)
        return err
    }
    return nil
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#convert_stream
func (client *PdfToTextClient) ConvertStream(inStream io.Reader) ([]byte, error) {
    data, errRead := ioutil.ReadAll(inStream)
    if errRead != nil {
        return nil, errRead
    }

    client.rawData["stream"] = data
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#convert_stream_to_stream
func (client *PdfToTextClient) ConvertStreamToStream(inStream io.Reader, outStream io.Writer) error {
    data, errRead := ioutil.ReadAll(inStream)
    if errRead != nil {
        return errRead
    }

    client.rawData["stream"] = data
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#convert_stream_to_file
func (client *PdfToTextClient) ConvertStreamToFile(inStream io.Reader, filePath string) error {
    if len(filePath) == 0 {
        return NewError(createInvalidValueMessage(filePath, "ConvertStreamToFile::file_path", "pdf-to-text", "The string must not be empty.", "convert_stream_to_file"), 470)
    }
    
    outputFile, err := os.Create(filePath)
    if err != nil {
        return err
    }
    err = client.ConvertStreamToStream(inStream, outputFile)
    outputFile.Close()
    if err != nil {
        os.Remove(filePath)
        return err
    }
    return nil
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#set_pdf_password
func (client *PdfToTextClient) SetPdfPassword(password string) *PdfToTextClient {
    client.fields["pdf_password"] = password
    return client
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#set_print_page_range
func (client *PdfToTextClient) SetPrintPageRange(pages string) *PdfToTextClient {
    client.fields["print_page_range"] = pages
    return client
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#set_no_layout
func (client *PdfToTextClient) SetNoLayout(value bool) *PdfToTextClient {
    client.fields["no_layout"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#set_eol
func (client *PdfToTextClient) SetEol(eol string) *PdfToTextClient {
    client.fields["eol"] = eol
    return client
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#set_page_break_mode
func (client *PdfToTextClient) SetPageBreakMode(mode string) *PdfToTextClient {
    client.fields["page_break_mode"] = mode
    return client
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#set_custom_page_break
func (client *PdfToTextClient) SetCustomPageBreak(pageBreak string) *PdfToTextClient {
    client.fields["custom_page_break"] = pageBreak
    return client
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#set_paragraph_mode
func (client *PdfToTextClient) SetParagraphMode(mode string) *PdfToTextClient {
    client.fields["paragraph_mode"] = mode
    return client
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#set_line_spacing_threshold
func (client *PdfToTextClient) SetLineSpacingThreshold(threshold string) *PdfToTextClient {
    client.fields["line_spacing_threshold"] = threshold
    return client
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#set_remove_hyphenation
func (client *PdfToTextClient) SetRemoveHyphenation(value bool) *PdfToTextClient {
    client.fields["remove_hyphenation"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#set_remove_empty_lines
func (client *PdfToTextClient) SetRemoveEmptyLines(value bool) *PdfToTextClient {
    client.fields["remove_empty_lines"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#set_crop_area_x
func (client *PdfToTextClient) SetCropAreaX(x int) *PdfToTextClient {
    client.fields["crop_area_x"] = strconv.Itoa(x)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#set_crop_area_y
func (client *PdfToTextClient) SetCropAreaY(y int) *PdfToTextClient {
    client.fields["crop_area_y"] = strconv.Itoa(y)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#set_crop_area_width
func (client *PdfToTextClient) SetCropAreaWidth(width int) *PdfToTextClient {
    client.fields["crop_area_width"] = strconv.Itoa(width)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#set_crop_area_height
func (client *PdfToTextClient) SetCropAreaHeight(height int) *PdfToTextClient {
    client.fields["crop_area_height"] = strconv.Itoa(height)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#set_crop_area
func (client *PdfToTextClient) SetCropArea(x int, y int, width int, height int) *PdfToTextClient {
    client.SetCropAreaX(x)
    client.SetCropAreaY(y)
    client.SetCropAreaWidth(width)
    client.SetCropAreaHeight(height)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#set_debug_log
func (client *PdfToTextClient) SetDebugLog(value bool) *PdfToTextClient {
    client.fields["debug_log"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#get_debug_log_url
func (client *PdfToTextClient) GetDebugLogUrl() string {
    return client.helper.getDebugLogUrl()
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#get_remaining_credit_count
func (client *PdfToTextClient) GetRemainingCreditCount() int {
    return client.helper.getRemainingCreditCount()
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#get_consumed_credit_count
func (client *PdfToTextClient) GetConsumedCreditCount() int {
    return client.helper.getConsumedCreditCount()
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#get_job_id
func (client *PdfToTextClient) GetJobId() string {
    return client.helper.getJobId()
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#get_page_count
func (client *PdfToTextClient) GetPageCount() int {
    return client.helper.getPageCount()
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#get_output_size
func (client *PdfToTextClient) GetOutputSize() int {
    return client.helper.getOutputSize()
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#get_version
func (client *PdfToTextClient) GetVersion() string {
    return fmt.Sprintf("client %s, API v2, converter %s", CLIENT_VERSION, client.helper.getConverterVersion())
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#set_tag
func (client *PdfToTextClient) SetTag(tag string) *PdfToTextClient {
    client.fields["tag"] = tag
    return client
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#set_http_proxy
func (client *PdfToTextClient) SetHttpProxy(proxy string) *PdfToTextClient {
    client.fields["http_proxy"] = proxy
    return client
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#set_https_proxy
func (client *PdfToTextClient) SetHttpsProxy(proxy string) *PdfToTextClient {
    client.fields["https_proxy"] = proxy
    return client
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#set_use_http
func (client *PdfToTextClient) SetUseHttp(value bool) *PdfToTextClient {
    client.helper.setUseHttp(value)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#set_client_user_agent
func (client *PdfToTextClient) SetClientUserAgent(agent string) *PdfToTextClient {
    client.helper.setUserAgent(agent)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#set_user_agent
func (client *PdfToTextClient) SetUserAgent(agent string) *PdfToTextClient {
    client.helper.setUserAgent(agent)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#set_proxy
func (client *PdfToTextClient) SetProxy(host string, port int, userName string, password string) *PdfToTextClient {
    client.helper.setProxy(host, port, userName, password)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-text-go/ref/#set_retry_count
func (client *PdfToTextClient) SetRetryCount(count int) *PdfToTextClient {
    client.helper.setRetryCount(count)
    return client
}

// Conversion from PDF to image.
//
// See https://pdfcrowd.com/api/pdf-to-image-go/
type PdfToImageClient struct {
    helper connectionHelper
    fields map[string]string
    files map[string]string
    rawData map[string][]byte
    fileId int
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#NewPdfToImageClient
func NewPdfToImageClient(userName string, apiKey string) PdfToImageClient {
    helper := newConnectionHelper(userName, apiKey)
    fields := map[string]string{
        "input_format": "pdf",
        "output_format": "png",
    }
    return PdfToImageClient{ helper, fields, make(map[string]string), make(map[string][]byte), 1}
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#convert_url
func (client *PdfToImageClient) ConvertUrl(url string) ([]byte, error) {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return nil, NewError(createInvalidValueMessage(url, "ConvertUrl", "pdf-to-image", "Supported protocols are http:// and https://.", "convert_url"), 470)
    }
    
    client.fields["url"] = url
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#convert_url_to_stream
func (client *PdfToImageClient) ConvertUrlToStream(url string, outStream io.Writer) error {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return NewError(createInvalidValueMessage(url, "ConvertUrlToStream::url", "pdf-to-image", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470)
    }
    
    client.fields["url"] = url
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#convert_url_to_file
func (client *PdfToImageClient) ConvertUrlToFile(url string, filePath string) error {
    if len(filePath) == 0 {
        return NewError(createInvalidValueMessage(filePath, "ConvertUrlToFile::file_path", "pdf-to-image", "The string must not be empty.", "convert_url_to_file"), 470)
    }
    
    outputFile, err := os.Create(filePath)
    if err != nil {
        return err
    }
    err = client.ConvertUrlToStream(url, outputFile)
    outputFile.Close()
    if err != nil {
        os.Remove(filePath)
        return err
    }
    return nil
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#convert_file
func (client *PdfToImageClient) ConvertFile(file string) ([]byte, error) {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return nil, NewError(createInvalidValueMessage(file, "ConvertFile", "pdf-to-image", "The file must exist and not be empty.", "convert_file"), 470)
    }
    
    client.files["file"] = file
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#convert_file_to_stream
func (client *PdfToImageClient) ConvertFileToStream(file string, outStream io.Writer) error {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return NewError(createInvalidValueMessage(file, "ConvertFileToStream::file", "pdf-to-image", "The file must exist and not be empty.", "convert_file_to_stream"), 470)
    }
    
    client.files["file"] = file
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#convert_file_to_file
func (client *PdfToImageClient) ConvertFileToFile(file string, filePath string) error {
    if len(filePath) == 0 {
        return NewError(createInvalidValueMessage(filePath, "ConvertFileToFile::file_path", "pdf-to-image", "The string must not be empty.", "convert_file_to_file"), 470)
    }
    
    outputFile, err := os.Create(filePath)
    if err != nil {
        return err
    }
    err = client.ConvertFileToStream(file, outputFile)
    outputFile.Close()
    if err != nil {
        os.Remove(filePath)
        return err
    }
    return nil
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#convert_raw_data
func (client *PdfToImageClient) ConvertRawData(data []byte) ([]byte, error) {
    client.rawData["file"] = data
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#convert_raw_data_to_stream
func (client *PdfToImageClient) ConvertRawDataToStream(data []byte, outStream io.Writer) error {
    client.rawData["file"] = data
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#convert_raw_data_to_file
func (client *PdfToImageClient) ConvertRawDataToFile(data []byte, filePath string) error {
    if len(filePath) == 0 {
        return NewError(createInvalidValueMessage(filePath, "ConvertRawDataToFile::file_path", "pdf-to-image", "The string must not be empty.", "convert_raw_data_to_file"), 470)
    }
    
    outputFile, err := os.Create(filePath)
    if err != nil {
        return err
    }
    err = client.ConvertRawDataToStream(data, outputFile)
    outputFile.Close()
    if err != nil {
        os.Remove(filePath)
        return err
    }
    return nil
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#convert_stream
func (client *PdfToImageClient) ConvertStream(inStream io.Reader) ([]byte, error) {
    data, errRead := ioutil.ReadAll(inStream)
    if errRead != nil {
        return nil, errRead
    }

    client.rawData["stream"] = data
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#convert_stream_to_stream
func (client *PdfToImageClient) ConvertStreamToStream(inStream io.Reader, outStream io.Writer) error {
    data, errRead := ioutil.ReadAll(inStream)
    if errRead != nil {
        return errRead
    }

    client.rawData["stream"] = data
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#convert_stream_to_file
func (client *PdfToImageClient) ConvertStreamToFile(inStream io.Reader, filePath string) error {
    if len(filePath) == 0 {
        return NewError(createInvalidValueMessage(filePath, "ConvertStreamToFile::file_path", "pdf-to-image", "The string must not be empty.", "convert_stream_to_file"), 470)
    }
    
    outputFile, err := os.Create(filePath)
    if err != nil {
        return err
    }
    err = client.ConvertStreamToStream(inStream, outputFile)
    outputFile.Close()
    if err != nil {
        os.Remove(filePath)
        return err
    }
    return nil
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#set_output_format
func (client *PdfToImageClient) SetOutputFormat(outputFormat string) *PdfToImageClient {
    client.fields["output_format"] = outputFormat
    return client
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#set_pdf_password
func (client *PdfToImageClient) SetPdfPassword(password string) *PdfToImageClient {
    client.fields["pdf_password"] = password
    return client
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#set_print_page_range
func (client *PdfToImageClient) SetPrintPageRange(pages string) *PdfToImageClient {
    client.fields["print_page_range"] = pages
    return client
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#set_dpi
func (client *PdfToImageClient) SetDpi(dpi int) *PdfToImageClient {
    client.fields["dpi"] = strconv.Itoa(dpi)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#is_zipped_output
func (client *PdfToImageClient) IsZippedOutput() bool {
    return client.fields["force_zip"] == "true" || client.GetPageCount() > 1
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#set_force_zip
func (client *PdfToImageClient) SetForceZip(value bool) *PdfToImageClient {
    client.fields["force_zip"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#set_use_cropbox
func (client *PdfToImageClient) SetUseCropbox(value bool) *PdfToImageClient {
    client.fields["use_cropbox"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#set_crop_area_x
func (client *PdfToImageClient) SetCropAreaX(x int) *PdfToImageClient {
    client.fields["crop_area_x"] = strconv.Itoa(x)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#set_crop_area_y
func (client *PdfToImageClient) SetCropAreaY(y int) *PdfToImageClient {
    client.fields["crop_area_y"] = strconv.Itoa(y)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#set_crop_area_width
func (client *PdfToImageClient) SetCropAreaWidth(width int) *PdfToImageClient {
    client.fields["crop_area_width"] = strconv.Itoa(width)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#set_crop_area_height
func (client *PdfToImageClient) SetCropAreaHeight(height int) *PdfToImageClient {
    client.fields["crop_area_height"] = strconv.Itoa(height)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#set_crop_area
func (client *PdfToImageClient) SetCropArea(x int, y int, width int, height int) *PdfToImageClient {
    client.SetCropAreaX(x)
    client.SetCropAreaY(y)
    client.SetCropAreaWidth(width)
    client.SetCropAreaHeight(height)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#set_use_grayscale
func (client *PdfToImageClient) SetUseGrayscale(value bool) *PdfToImageClient {
    client.fields["use_grayscale"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#set_debug_log
func (client *PdfToImageClient) SetDebugLog(value bool) *PdfToImageClient {
    client.fields["debug_log"] = strconv.FormatBool(value)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#get_debug_log_url
func (client *PdfToImageClient) GetDebugLogUrl() string {
    return client.helper.getDebugLogUrl()
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#get_remaining_credit_count
func (client *PdfToImageClient) GetRemainingCreditCount() int {
    return client.helper.getRemainingCreditCount()
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#get_consumed_credit_count
func (client *PdfToImageClient) GetConsumedCreditCount() int {
    return client.helper.getConsumedCreditCount()
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#get_job_id
func (client *PdfToImageClient) GetJobId() string {
    return client.helper.getJobId()
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#get_page_count
func (client *PdfToImageClient) GetPageCount() int {
    return client.helper.getPageCount()
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#get_output_size
func (client *PdfToImageClient) GetOutputSize() int {
    return client.helper.getOutputSize()
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#get_version
func (client *PdfToImageClient) GetVersion() string {
    return fmt.Sprintf("client %s, API v2, converter %s", CLIENT_VERSION, client.helper.getConverterVersion())
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#set_tag
func (client *PdfToImageClient) SetTag(tag string) *PdfToImageClient {
    client.fields["tag"] = tag
    return client
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#set_http_proxy
func (client *PdfToImageClient) SetHttpProxy(proxy string) *PdfToImageClient {
    client.fields["http_proxy"] = proxy
    return client
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#set_https_proxy
func (client *PdfToImageClient) SetHttpsProxy(proxy string) *PdfToImageClient {
    client.fields["https_proxy"] = proxy
    return client
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#set_use_http
func (client *PdfToImageClient) SetUseHttp(value bool) *PdfToImageClient {
    client.helper.setUseHttp(value)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#set_client_user_agent
func (client *PdfToImageClient) SetClientUserAgent(agent string) *PdfToImageClient {
    client.helper.setUserAgent(agent)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#set_user_agent
func (client *PdfToImageClient) SetUserAgent(agent string) *PdfToImageClient {
    client.helper.setUserAgent(agent)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#set_proxy
func (client *PdfToImageClient) SetProxy(host string, port int, userName string, password string) *PdfToImageClient {
    client.helper.setProxy(host, port, userName, password)
    return client
}

// See https://pdfcrowd.com/api/pdf-to-image-go/ref/#set_retry_count
func (client *PdfToImageClient) SetRetryCount(count int) *PdfToImageClient {
    client.helper.setRetryCount(count)
    return client
}


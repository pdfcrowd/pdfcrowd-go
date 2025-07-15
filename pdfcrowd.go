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

const CLIENT_VERSION = "6.5.2"

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
    helper.setUserAgent("pdfcrowd_go_client/6.5.2 (https://pdfcrowd.com)")
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
type HtmlToPdfClient struct {
    helper connectionHelper
    fields map[string]string
    files map[string]string
    rawData map[string][]byte
    fileId int
}

// Constructor for the PDFCrowd API client.
//
// userName - Your username at PDFCrowd.
// apiKey - Your API key.
func NewHtmlToPdfClient(userName string, apiKey string) HtmlToPdfClient {
    helper := newConnectionHelper(userName, apiKey)
    fields := map[string]string{
        "input_format": "html",
        "output_format": "pdf",
    }
    return HtmlToPdfClient{ helper, fields, make(map[string]string), make(map[string][]byte), 1}
}

// Convert a web page.
//
// url - The address of the web page to convert. Supported protocols are http:// and https://.
func (client *HtmlToPdfClient) ConvertUrl(url string) ([]byte, error) {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return nil, NewError(createInvalidValueMessage(url, "ConvertUrl", "html-to-pdf", "Supported protocols are http:// and https://.", "convert_url"), 470)
    }
    
    client.fields["url"] = url
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert a web page and write the result to an output stream.
//
// url - The address of the web page to convert. Supported protocols are http:// and https://.
// outStream - The output stream that will contain the conversion output.
func (client *HtmlToPdfClient) ConvertUrlToStream(url string, outStream io.Writer) error {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return NewError(createInvalidValueMessage(url, "ConvertUrlToStream::url", "html-to-pdf", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470)
    }
    
    client.fields["url"] = url
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert a web page and write the result to a local file.
//
// url - The address of the web page to convert. Supported protocols are http:// and https://.
// filePath - The output file path. The string must not be empty.
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

// Convert a local file.
//
// file - The path to a local file to convert. The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). If the HTML document refers to local external assets (images, style sheets, javascript), zip the document together with the assets. The file must exist and not be empty. The file name must have a valid extension.
func (client *HtmlToPdfClient) ConvertFile(file string) ([]byte, error) {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return nil, NewError(createInvalidValueMessage(file, "ConvertFile", "html-to-pdf", "The file must exist and not be empty.", "convert_file"), 470)
    }
    
    client.files["file"] = file
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert a local file and write the result to an output stream.
//
// file - The path to a local file to convert. The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). If the HTML document refers to local external assets (images, style sheets, javascript), zip the document together with the assets. The file must exist and not be empty. The file name must have a valid extension.
// outStream - The output stream that will contain the conversion output.
func (client *HtmlToPdfClient) ConvertFileToStream(file string, outStream io.Writer) error {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return NewError(createInvalidValueMessage(file, "ConvertFileToStream::file", "html-to-pdf", "The file must exist and not be empty.", "convert_file_to_stream"), 470)
    }
    
    client.files["file"] = file
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert a local file and write the result to a local file.
//
// file - The path to a local file to convert. The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). If the HTML document refers to local external assets (images, style sheets, javascript), zip the document together with the assets. The file must exist and not be empty. The file name must have a valid extension.
// filePath - The output file path. The string must not be empty.
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

// Convert a string.
//
// text - The string content to convert. The string must not be empty.
func (client *HtmlToPdfClient) ConvertString(text string) ([]byte, error) {
    if len(text) == 0 {
        return nil, NewError(createInvalidValueMessage(text, "ConvertString", "html-to-pdf", "The string must not be empty.", "convert_string"), 470)
    }
    
    client.fields["text"] = text
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert a string and write the output to an output stream.
//
// text - The string content to convert. The string must not be empty.
// outStream - The output stream that will contain the conversion output.
func (client *HtmlToPdfClient) ConvertStringToStream(text string, outStream io.Writer) error {
    if len(text) == 0 {
        return NewError(createInvalidValueMessage(text, "ConvertStringToStream::text", "html-to-pdf", "The string must not be empty.", "convert_string_to_stream"), 470)
    }
    
    client.fields["text"] = text
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert a string and write the output to a file.
//
// text - The string content to convert. The string must not be empty.
// filePath - The output file path. The string must not be empty.
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

// Convert the contents of an input stream.
//
// inStream - The input stream with source data. The stream can contain either HTML code or an archive (.zip, .tar.gz, .tar.bz2).The archive can contain HTML code and its external assets (images, style sheets, javascript).
func (client *HtmlToPdfClient) ConvertStream(inStream io.Reader) ([]byte, error) {
    data, errRead := ioutil.ReadAll(inStream)
    if errRead != nil {
        return nil, errRead
    }

    client.rawData["stream"] = data
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert the contents of an input stream and write the result to an output stream.
//
// inStream - The input stream with source data. The stream can contain either HTML code or an archive (.zip, .tar.gz, .tar.bz2).The archive can contain HTML code and its external assets (images, style sheets, javascript).
// outStream - The output stream that will contain the conversion output.
func (client *HtmlToPdfClient) ConvertStreamToStream(inStream io.Reader, outStream io.Writer) error {
    data, errRead := ioutil.ReadAll(inStream)
    if errRead != nil {
        return errRead
    }

    client.rawData["stream"] = data
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert the contents of an input stream and write the result to a local file.
//
// inStream - The input stream with source data. The stream can contain either HTML code or an archive (.zip, .tar.gz, .tar.bz2).The archive can contain HTML code and its external assets (images, style sheets, javascript).
// filePath - The output file path. The string must not be empty.
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

// Set the file name of the main HTML document stored in the input archive. If not specified, the first HTML file in the archive is used for conversion. Use this method if the input archive contains multiple HTML documents.
//
// filename - The file name.
func (client *HtmlToPdfClient) SetZipMainFilename(filename string) *HtmlToPdfClient {
    client.fields["zip_main_filename"] = filename
    return client
}

// Set the output page size.
//
// size - Allowed values are A0, A1, A2, A3, A4, A5, A6, Letter.
func (client *HtmlToPdfClient) SetPageSize(size string) *HtmlToPdfClient {
    client.fields["page_size"] = size
    return client
}

// Set the output page width. The safe maximum is 200in otherwise some PDF viewers may be unable to open the PDF.
//
// width - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *HtmlToPdfClient) SetPageWidth(width string) *HtmlToPdfClient {
    client.fields["page_width"] = width
    return client
}

// Set the output page height. Use -1 for a single page PDF. The safe maximum is 200in otherwise some PDF viewers may be unable to open the PDF.
//
// height - The value must be -1 or specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *HtmlToPdfClient) SetPageHeight(height string) *HtmlToPdfClient {
    client.fields["page_height"] = height
    return client
}

// Set the output page dimensions.
//
// width - Set the output page width. The safe maximum is 200in otherwise some PDF viewers may be unable to open the PDF. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
// height - Set the output page height. Use -1 for a single page PDF. The safe maximum is 200in otherwise some PDF viewers may be unable to open the PDF. The value must be -1 or specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *HtmlToPdfClient) SetPageDimensions(width string, height string) *HtmlToPdfClient {
    client.SetPageWidth(width)
    client.SetPageHeight(height)
    return client
}

// Set the output page orientation.
//
// orientation - Allowed values are landscape, portrait.
func (client *HtmlToPdfClient) SetOrientation(orientation string) *HtmlToPdfClient {
    client.fields["orientation"] = orientation
    return client
}

// Set the output page top margin.
//
// top - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *HtmlToPdfClient) SetMarginTop(top string) *HtmlToPdfClient {
    client.fields["margin_top"] = top
    return client
}

// Set the output page right margin.
//
// right - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *HtmlToPdfClient) SetMarginRight(right string) *HtmlToPdfClient {
    client.fields["margin_right"] = right
    return client
}

// Set the output page bottom margin.
//
// bottom - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *HtmlToPdfClient) SetMarginBottom(bottom string) *HtmlToPdfClient {
    client.fields["margin_bottom"] = bottom
    return client
}

// Set the output page left margin.
//
// left - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *HtmlToPdfClient) SetMarginLeft(left string) *HtmlToPdfClient {
    client.fields["margin_left"] = left
    return client
}

// Disable page margins.
//
// value - Set to true to disable margins.
func (client *HtmlToPdfClient) SetNoMargins(value bool) *HtmlToPdfClient {
    client.fields["no_margins"] = strconv.FormatBool(value)
    return client
}

// Set the output page margins.
//
// top - Set the output page top margin. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
// right - Set the output page right margin. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
// bottom - Set the output page bottom margin. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
// left - Set the output page left margin. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *HtmlToPdfClient) SetPageMargins(top string, right string, bottom string, left string) *HtmlToPdfClient {
    client.SetMarginTop(top)
    client.SetMarginRight(right)
    client.SetMarginBottom(bottom)
    client.SetMarginLeft(left)
    return client
}

// Set the page range to print.
//
// pages - A comma separated list of page numbers or ranges. Special strings may be used, such as 'odd', 'even' and 'last'.
func (client *HtmlToPdfClient) SetPrintPageRange(pages string) *HtmlToPdfClient {
    client.fields["print_page_range"] = pages
    return client
}

// Set the viewport width for formatting the HTML content when generating a PDF. By specifying a viewport width, you can control how the content is rendered, ensuring it mimics the appearance on various devices or matches specific design requirements.
//
// width - The width of the viewport. The value must be 'balanced', 'small', 'medium', 'large', 'extra-large', or a number in the range 96-65000px.
func (client *HtmlToPdfClient) SetContentViewportWidth(width string) *HtmlToPdfClient {
    client.fields["content_viewport_width"] = width
    return client
}

// Set the viewport height for formatting the HTML content when generating a PDF. By specifying a viewport height, you can enforce loading of lazy-loaded images and also affect vertical positioning of absolutely positioned elements within the content.
//
// height - The viewport height. The value must be 'auto', 'large', or a number.
func (client *HtmlToPdfClient) SetContentViewportHeight(height string) *HtmlToPdfClient {
    client.fields["content_viewport_height"] = height
    return client
}

// Specifies the mode for fitting the HTML content to the print area by upscaling or downscaling it.
//
// mode - The fitting mode. Allowed values are auto, smart-scaling, no-scaling, viewport-width, content-width, single-page, single-page-ratio.
func (client *HtmlToPdfClient) SetContentFitMode(mode string) *HtmlToPdfClient {
    client.fields["content_fit_mode"] = mode
    return client
}

// Specifies which blank pages to exclude from the output document.
//
// pages - The empty page behavior. Allowed values are trailing, all, none.
func (client *HtmlToPdfClient) SetRemoveBlankPages(pages string) *HtmlToPdfClient {
    client.fields["remove_blank_pages"] = pages
    return client
}

// Load an HTML code from the specified URL and use it as the page header. The following classes can be used in the HTML. The content of the respective elements will be expanded as follows: pdfcrowd-page-count - the total page count of printed pages pdfcrowd-page-number - the current page number pdfcrowd-source-url - the source URL of the converted document pdfcrowd-source-title - the title of the converted document The following attributes can be used: data-pdfcrowd-number-format - specifies the type of the used numerals. Allowed values: arabic - Arabic numerals, they are used by default roman - Roman numerals eastern-arabic - Eastern Arabic numerals bengali - Bengali numerals devanagari - Devanagari numerals thai - Thai numerals east-asia - Chinese, Vietnamese, Japanese and Korean numerals chinese-formal - Chinese formal numerals Please contact us if you need another type of numerals. Example: <span class='pdfcrowd-page-number' data-pdfcrowd-number-format='roman'></span> data-pdfcrowd-placement - specifies where to place the source URL. Allowed values: The URL is inserted to the content Example: <span class='pdfcrowd-source-url'></span> will produce <span>http://example.com</span> href - the URL is set to the href attribute Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href'>Link to source</a> will produce <a href='http://example.com'>Link to source</a> href-and-content - the URL is set to the href attribute and to the content Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href-and-content'></a> will produce <a href='http://example.com'>http://example.com</a>
//
// url - Supported protocols are http:// and https://.
func (client *HtmlToPdfClient) SetHeaderUrl(url string) *HtmlToPdfClient {
    client.fields["header_url"] = url
    return client
}

// Use the specified HTML code as the page header. The following classes can be used in the HTML. The content of the respective elements will be expanded as follows: pdfcrowd-page-count - the total page count of printed pages pdfcrowd-page-number - the current page number pdfcrowd-source-url - the source URL of the converted document pdfcrowd-source-title - the title of the converted document The following attributes can be used: data-pdfcrowd-number-format - specifies the type of the used numerals. Allowed values: arabic - Arabic numerals, they are used by default roman - Roman numerals eastern-arabic - Eastern Arabic numerals bengali - Bengali numerals devanagari - Devanagari numerals thai - Thai numerals east-asia - Chinese, Vietnamese, Japanese and Korean numerals chinese-formal - Chinese formal numerals Please contact us if you need another type of numerals. Example: <span class='pdfcrowd-page-number' data-pdfcrowd-number-format='roman'></span> data-pdfcrowd-placement - specifies where to place the source URL. Allowed values: The URL is inserted to the content Example: <span class='pdfcrowd-source-url'></span> will produce <span>http://example.com</span> href - the URL is set to the href attribute Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href'>Link to source</a> will produce <a href='http://example.com'>Link to source</a> href-and-content - the URL is set to the href attribute and to the content Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href-and-content'></a> will produce <a href='http://example.com'>http://example.com</a>
//
// html - The string must not be empty.
func (client *HtmlToPdfClient) SetHeaderHtml(html string) *HtmlToPdfClient {
    client.fields["header_html"] = html
    return client
}

// Set the header height.
//
// height - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *HtmlToPdfClient) SetHeaderHeight(height string) *HtmlToPdfClient {
    client.fields["header_height"] = height
    return client
}

// Set the file name of the header HTML document stored in the input archive. Use this method if the input archive contains multiple HTML documents.
//
// filename - The file name.
func (client *HtmlToPdfClient) SetZipHeaderFilename(filename string) *HtmlToPdfClient {
    client.fields["zip_header_filename"] = filename
    return client
}

// Load an HTML code from the specified URL and use it as the page footer. The following classes can be used in the HTML. The content of the respective elements will be expanded as follows: pdfcrowd-page-count - the total page count of printed pages pdfcrowd-page-number - the current page number pdfcrowd-source-url - the source URL of the converted document pdfcrowd-source-title - the title of the converted document The following attributes can be used: data-pdfcrowd-number-format - specifies the type of the used numerals. Allowed values: arabic - Arabic numerals, they are used by default roman - Roman numerals eastern-arabic - Eastern Arabic numerals bengali - Bengali numerals devanagari - Devanagari numerals thai - Thai numerals east-asia - Chinese, Vietnamese, Japanese and Korean numerals chinese-formal - Chinese formal numerals Please contact us if you need another type of numerals. Example: <span class='pdfcrowd-page-number' data-pdfcrowd-number-format='roman'></span> data-pdfcrowd-placement - specifies where to place the source URL. Allowed values: The URL is inserted to the content Example: <span class='pdfcrowd-source-url'></span> will produce <span>http://example.com</span> href - the URL is set to the href attribute Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href'>Link to source</a> will produce <a href='http://example.com'>Link to source</a> href-and-content - the URL is set to the href attribute and to the content Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href-and-content'></a> will produce <a href='http://example.com'>http://example.com</a>
//
// url - Supported protocols are http:// and https://.
func (client *HtmlToPdfClient) SetFooterUrl(url string) *HtmlToPdfClient {
    client.fields["footer_url"] = url
    return client
}

// Use the specified HTML as the page footer. The following classes can be used in the HTML. The content of the respective elements will be expanded as follows: pdfcrowd-page-count - the total page count of printed pages pdfcrowd-page-number - the current page number pdfcrowd-source-url - the source URL of the converted document pdfcrowd-source-title - the title of the converted document The following attributes can be used: data-pdfcrowd-number-format - specifies the type of the used numerals. Allowed values: arabic - Arabic numerals, they are used by default roman - Roman numerals eastern-arabic - Eastern Arabic numerals bengali - Bengali numerals devanagari - Devanagari numerals thai - Thai numerals east-asia - Chinese, Vietnamese, Japanese and Korean numerals chinese-formal - Chinese formal numerals Please contact us if you need another type of numerals. Example: <span class='pdfcrowd-page-number' data-pdfcrowd-number-format='roman'></span> data-pdfcrowd-placement - specifies where to place the source URL. Allowed values: The URL is inserted to the content Example: <span class='pdfcrowd-source-url'></span> will produce <span>http://example.com</span> href - the URL is set to the href attribute Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href'>Link to source</a> will produce <a href='http://example.com'>Link to source</a> href-and-content - the URL is set to the href attribute and to the content Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href-and-content'></a> will produce <a href='http://example.com'>http://example.com</a>
//
// html - The string must not be empty.
func (client *HtmlToPdfClient) SetFooterHtml(html string) *HtmlToPdfClient {
    client.fields["footer_html"] = html
    return client
}

// Set the footer height.
//
// height - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *HtmlToPdfClient) SetFooterHeight(height string) *HtmlToPdfClient {
    client.fields["footer_height"] = height
    return client
}

// Set the file name of the footer HTML document stored in the input archive. Use this method if the input archive contains multiple HTML documents.
//
// filename - The file name.
func (client *HtmlToPdfClient) SetZipFooterFilename(filename string) *HtmlToPdfClient {
    client.fields["zip_footer_filename"] = filename
    return client
}

// Disable horizontal page margins for header and footer. The header/footer contents width will be equal to the physical page width.
//
// value - Set to true to disable horizontal margins for header and footer.
func (client *HtmlToPdfClient) SetNoHeaderFooterHorizontalMargins(value bool) *HtmlToPdfClient {
    client.fields["no_header_footer_horizontal_margins"] = strconv.FormatBool(value)
    return client
}

// The page header content is not printed on the specified pages. To remove the entire header area, use the conversion config.
//
// pages - List of physical page numbers. Negative numbers count backwards from the last page: -1 is the last page, -2 is the last but one page, and so on. A comma separated list of page numbers.
func (client *HtmlToPdfClient) SetExcludeHeaderOnPages(pages string) *HtmlToPdfClient {
    client.fields["exclude_header_on_pages"] = pages
    return client
}

// The page footer content is not printed on the specified pages. To remove the entire footer area, use the conversion config.
//
// pages - List of physical page numbers. Negative numbers count backwards from the last page: -1 is the last page, -2 is the last but one page, and so on. A comma separated list of page numbers.
func (client *HtmlToPdfClient) SetExcludeFooterOnPages(pages string) *HtmlToPdfClient {
    client.fields["exclude_footer_on_pages"] = pages
    return client
}

// Set the scaling factor (zoom) for the header and footer.
//
// factor - The percentage value. The accepted range is 10-500.
func (client *HtmlToPdfClient) SetHeaderFooterScaleFactor(factor int) *HtmlToPdfClient {
    client.fields["header_footer_scale_factor"] = strconv.Itoa(factor)
    return client
}

// Set an offset between physical and logical page numbers.
//
// offset - Integer specifying page offset.
func (client *HtmlToPdfClient) SetPageNumberingOffset(offset int) *HtmlToPdfClient {
    client.fields["page_numbering_offset"] = strconv.Itoa(offset)
    return client
}

// Apply a watermark to each page of the output PDF file. A watermark can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the watermark.
//
// watermark - The file path to a local file. The file must exist and not be empty.
func (client *HtmlToPdfClient) SetPageWatermark(watermark string) *HtmlToPdfClient {
    client.files["page_watermark"] = watermark
    return client
}

// Load a file from the specified URL and apply the file as a watermark to each page of the output PDF. A watermark can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the watermark.
//
// url - Supported protocols are http:// and https://.
func (client *HtmlToPdfClient) SetPageWatermarkUrl(url string) *HtmlToPdfClient {
    client.fields["page_watermark_url"] = url
    return client
}

// Apply each page of a watermark to the corresponding page of the output PDF. A watermark can be either a PDF or an image.
//
// watermark - The file path to a local file. The file must exist and not be empty.
func (client *HtmlToPdfClient) SetMultipageWatermark(watermark string) *HtmlToPdfClient {
    client.files["multipage_watermark"] = watermark
    return client
}

// Load a file from the specified URL and apply each page of the file as a watermark to the corresponding page of the output PDF. A watermark can be either a PDF or an image.
//
// url - Supported protocols are http:// and https://.
func (client *HtmlToPdfClient) SetMultipageWatermarkUrl(url string) *HtmlToPdfClient {
    client.fields["multipage_watermark_url"] = url
    return client
}

// Apply a background to each page of the output PDF file. A background can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the background.
//
// background - The file path to a local file. The file must exist and not be empty.
func (client *HtmlToPdfClient) SetPageBackground(background string) *HtmlToPdfClient {
    client.files["page_background"] = background
    return client
}

// Load a file from the specified URL and apply the file as a background to each page of the output PDF. A background can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the background.
//
// url - Supported protocols are http:// and https://.
func (client *HtmlToPdfClient) SetPageBackgroundUrl(url string) *HtmlToPdfClient {
    client.fields["page_background_url"] = url
    return client
}

// Apply each page of a background to the corresponding page of the output PDF. A background can be either a PDF or an image.
//
// background - The file path to a local file. The file must exist and not be empty.
func (client *HtmlToPdfClient) SetMultipageBackground(background string) *HtmlToPdfClient {
    client.files["multipage_background"] = background
    return client
}

// Load a file from the specified URL and apply each page of the file as a background to the corresponding page of the output PDF. A background can be either a PDF or an image.
//
// url - Supported protocols are http:// and https://.
func (client *HtmlToPdfClient) SetMultipageBackgroundUrl(url string) *HtmlToPdfClient {
    client.fields["multipage_background_url"] = url
    return client
}

// The page background color in RGB or RGBA hexadecimal format. The color fills the entire page regardless of the margins.
//
// color - The value must be in RRGGBB or RRGGBBAA hexadecimal format.
func (client *HtmlToPdfClient) SetPageBackgroundColor(color string) *HtmlToPdfClient {
    client.fields["page_background_color"] = color
    return client
}

// Use the print version of the page if available (@media print).
//
// value - Set to true to use the print version of the page.
func (client *HtmlToPdfClient) SetUsePrintMedia(value bool) *HtmlToPdfClient {
    client.fields["use_print_media"] = strconv.FormatBool(value)
    return client
}

// Do not print the background graphics.
//
// value - Set to true to disable the background graphics.
func (client *HtmlToPdfClient) SetNoBackground(value bool) *HtmlToPdfClient {
    client.fields["no_background"] = strconv.FormatBool(value)
    return client
}

// Do not execute JavaScript.
//
// value - Set to true to disable JavaScript in web pages.
func (client *HtmlToPdfClient) SetDisableJavascript(value bool) *HtmlToPdfClient {
    client.fields["disable_javascript"] = strconv.FormatBool(value)
    return client
}

// Do not load images.
//
// value - Set to true to disable loading of images.
func (client *HtmlToPdfClient) SetDisableImageLoading(value bool) *HtmlToPdfClient {
    client.fields["disable_image_loading"] = strconv.FormatBool(value)
    return client
}

// Disable loading fonts from remote sources.
//
// value - Set to true disable loading remote fonts.
func (client *HtmlToPdfClient) SetDisableRemoteFonts(value bool) *HtmlToPdfClient {
    client.fields["disable_remote_fonts"] = strconv.FormatBool(value)
    return client
}

// Use a mobile user agent.
//
// value - Set to true to use a mobile user agent.
func (client *HtmlToPdfClient) SetUseMobileUserAgent(value bool) *HtmlToPdfClient {
    client.fields["use_mobile_user_agent"] = strconv.FormatBool(value)
    return client
}

// Specifies how iframes are handled.
//
// iframes - Allowed values are all, same-origin, none.
func (client *HtmlToPdfClient) SetLoadIframes(iframes string) *HtmlToPdfClient {
    client.fields["load_iframes"] = iframes
    return client
}

// Try to block ads. Enabling this option can produce smaller output and speed up the conversion.
//
// value - Set to true to block ads in web pages.
func (client *HtmlToPdfClient) SetBlockAds(value bool) *HtmlToPdfClient {
    client.fields["block_ads"] = strconv.FormatBool(value)
    return client
}

// Set the default HTML content text encoding.
//
// encoding - The text encoding of the HTML content.
func (client *HtmlToPdfClient) SetDefaultEncoding(encoding string) *HtmlToPdfClient {
    client.fields["default_encoding"] = encoding
    return client
}

// Set the locale for the conversion. This may affect the output format of dates, times and numbers.
//
// locale - The locale code according to ISO 639.
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

// Set credentials to access HTTP base authentication protected websites.
//
// userName - Set the HTTP authentication user name.
// password - Set the HTTP authentication password.
func (client *HtmlToPdfClient) SetHttpAuth(userName string, password string) *HtmlToPdfClient {
    client.SetHttpAuthUserName(userName)
    client.SetHttpAuthPassword(password)
    return client
}

// Set HTTP cookies to be included in all requests made by the converter.
//
// cookies - The cookie string.
func (client *HtmlToPdfClient) SetCookies(cookies string) *HtmlToPdfClient {
    client.fields["cookies"] = cookies
    return client
}

// Do not allow insecure HTTPS connections.
//
// value - Set to true to enable SSL certificate verification.
func (client *HtmlToPdfClient) SetVerifySslCertificates(value bool) *HtmlToPdfClient {
    client.fields["verify_ssl_certificates"] = strconv.FormatBool(value)
    return client
}

// Abort the conversion if the main URL HTTP status code is greater than or equal to 400.
//
// failOnError - Set to true to abort the conversion.
func (client *HtmlToPdfClient) SetFailOnMainUrlError(failOnError bool) *HtmlToPdfClient {
    client.fields["fail_on_main_url_error"] = strconv.FormatBool(failOnError)
    return client
}

// Abort the conversion if any of the sub-request HTTP status code is greater than or equal to 400 or if some sub-requests are still pending. See details in a debug log.
//
// failOnError - Set to true to abort the conversion.
func (client *HtmlToPdfClient) SetFailOnAnyUrlError(failOnError bool) *HtmlToPdfClient {
    client.fields["fail_on_any_url_error"] = strconv.FormatBool(failOnError)
    return client
}

// Do not send the X-Pdfcrowd HTTP header in PDFCrowd HTTP requests.
//
// value - Set to true to disable sending X-Pdfcrowd HTTP header.
func (client *HtmlToPdfClient) SetNoXpdfcrowdHeader(value bool) *HtmlToPdfClient {
    client.fields["no_xpdfcrowd_header"] = strconv.FormatBool(value)
    return client
}

// Specifies behavior in presence of CSS @page rules. It may affect the page size, margins and orientation.
//
// mode - The page rule mode. Allowed values are default, mode1, mode2.
func (client *HtmlToPdfClient) SetCssPageRuleMode(mode string) *HtmlToPdfClient {
    client.fields["css_page_rule_mode"] = mode
    return client
}

// Apply custom CSS to the input HTML document. It allows you to modify the visual appearance and layout of your HTML content dynamically. Tip: Using !important in custom CSS provides a way to prioritize and override conflicting styles.
//
// css - A string containing valid CSS. The string must not be empty.
func (client *HtmlToPdfClient) SetCustomCss(css string) *HtmlToPdfClient {
    client.fields["custom_css"] = css
    return client
}

// Run a custom JavaScript after the document is loaded and ready to print. The script is intended for post-load DOM manipulation (add/remove elements, update CSS, ...). In addition to the standard browser APIs, the custom JavaScript code can use helper functions from our JavaScript library.
//
// javascript - A string containing a JavaScript code. The string must not be empty.
func (client *HtmlToPdfClient) SetCustomJavascript(javascript string) *HtmlToPdfClient {
    client.fields["custom_javascript"] = javascript
    return client
}

// Run a custom JavaScript right after the document is loaded. The script is intended for early DOM manipulation (add/remove elements, update CSS, ...). In addition to the standard browser APIs, the custom JavaScript code can use helper functions from our JavaScript library.
//
// javascript - A string containing a JavaScript code. The string must not be empty.
func (client *HtmlToPdfClient) SetOnLoadJavascript(javascript string) *HtmlToPdfClient {
    client.fields["on_load_javascript"] = javascript
    return client
}

// Set a custom HTTP header to be included in all requests made by the converter.
//
// header - A string containing the header name and value separated by a colon.
func (client *HtmlToPdfClient) SetCustomHttpHeader(header string) *HtmlToPdfClient {
    client.fields["custom_http_header"] = header
    return client
}

// Wait the specified number of milliseconds to finish all JavaScript after the document is loaded. Your license defines the maximum wait time by "Max Delay" parameter.
//
// delay - The number of milliseconds to wait. Must be a positive integer or 0.
func (client *HtmlToPdfClient) SetJavascriptDelay(delay int) *HtmlToPdfClient {
    client.fields["javascript_delay"] = strconv.Itoa(delay)
    return client
}

// Convert only the specified element from the main document and its children. The element is specified by one or more CSS selectors. If the element is not found, the conversion fails. If multiple elements are found, the first one is used.
//
// selectors - One or more CSS selectors separated by commas. The string must not be empty.
func (client *HtmlToPdfClient) SetElementToConvert(selectors string) *HtmlToPdfClient {
    client.fields["element_to_convert"] = selectors
    return client
}

// Specify the DOM handling when only a part of the document is converted. This can affect the CSS rules used.
//
// mode - Allowed values are cut-out, remove-siblings, hide-siblings.
func (client *HtmlToPdfClient) SetElementToConvertMode(mode string) *HtmlToPdfClient {
    client.fields["element_to_convert_mode"] = mode
    return client
}

// Wait for the specified element in a source document. The element is specified by one or more CSS selectors. The element is searched for in the main document and all iframes. If the element is not found, the conversion fails. Your license defines the maximum wait time by "Max Delay" parameter.
//
// selectors - One or more CSS selectors separated by commas. The string must not be empty.
func (client *HtmlToPdfClient) SetWaitForElement(selectors string) *HtmlToPdfClient {
    client.fields["wait_for_element"] = selectors
    return client
}

// The main HTML element for conversion is detected automatically.
//
// value - Set to true to detect the main element.
func (client *HtmlToPdfClient) SetAutoDetectElementToConvert(value bool) *HtmlToPdfClient {
    client.fields["auto_detect_element_to_convert"] = strconv.FormatBool(value)
    return client
}

// The input HTML is automatically enhanced to improve the readability.
//
// enhancements - Allowed values are none, readability-v1, readability-v2, readability-v3, readability-v4.
func (client *HtmlToPdfClient) SetReadabilityEnhancements(enhancements string) *HtmlToPdfClient {
    client.fields["readability_enhancements"] = enhancements
    return client
}

// Set the viewport width in pixels. The viewport is the user's visible area of the page.
//
// width - The accepted range is 96-65000.
func (client *HtmlToPdfClient) SetViewportWidth(width int) *HtmlToPdfClient {
    client.fields["viewport_width"] = strconv.Itoa(width)
    return client
}

// Set the viewport height in pixels. The viewport is the user's visible area of the page. If the input HTML uses lazily loaded images, try using a large value that covers the entire height of the HTML, e.g. 100000.
//
// height - Must be a positive integer.
func (client *HtmlToPdfClient) SetViewportHeight(height int) *HtmlToPdfClient {
    client.fields["viewport_height"] = strconv.Itoa(height)
    return client
}

// Set the viewport size. The viewport is the user's visible area of the page.
//
// width - Set the viewport width in pixels. The viewport is the user's visible area of the page. The accepted range is 96-65000.
// height - Set the viewport height in pixels. The viewport is the user's visible area of the page. If the input HTML uses lazily loaded images, try using a large value that covers the entire height of the HTML, e.g. 100000. Must be a positive integer.
func (client *HtmlToPdfClient) SetViewport(width int, height int) *HtmlToPdfClient {
    client.SetViewportWidth(width)
    client.SetViewportHeight(height)
    return client
}

// Set the rendering mode of the page, allowing control over how content is displayed.
//
// mode - The rendering mode. Allowed values are default, viewport.
func (client *HtmlToPdfClient) SetRenderingMode(mode string) *HtmlToPdfClient {
    client.fields["rendering_mode"] = mode
    return client
}

// Specifies the scaling mode used for fitting the HTML contents to the print area.
//
// mode - The smart scaling mode. Allowed values are default, disabled, viewport-fit, content-fit, single-page-fit, single-page-fit-ex, mode1.
func (client *HtmlToPdfClient) SetSmartScalingMode(mode string) *HtmlToPdfClient {
    client.fields["smart_scaling_mode"] = mode
    return client
}

// Set the scaling factor (zoom) for the main page area.
//
// factor - The percentage value. The accepted range is 10-500.
func (client *HtmlToPdfClient) SetScaleFactor(factor int) *HtmlToPdfClient {
    client.fields["scale_factor"] = strconv.Itoa(factor)
    return client
}

// Set the quality of embedded JPEG images. A lower quality results in a smaller PDF file but can lead to compression artifacts.
//
// quality - The percentage value. The accepted range is 1-100.
func (client *HtmlToPdfClient) SetJpegQuality(quality int) *HtmlToPdfClient {
    client.fields["jpeg_quality"] = strconv.Itoa(quality)
    return client
}

// Specify which image types will be converted to JPEG. Converting lossless compression image formats (PNG, GIF, ...) to JPEG may result in a smaller PDF file.
//
// images - The image category. Allowed values are none, opaque, all.
func (client *HtmlToPdfClient) SetConvertImagesToJpeg(images string) *HtmlToPdfClient {
    client.fields["convert_images_to_jpeg"] = images
    return client
}

// Set the DPI of images in PDF. A lower DPI may result in a smaller PDF file. If the specified DPI is higher than the actual image DPI, the original image DPI is retained (no upscaling is performed). Use 0 to leave the images unaltered.
//
// dpi - The DPI value. Must be a positive integer or 0.
func (client *HtmlToPdfClient) SetImageDpi(dpi int) *HtmlToPdfClient {
    client.fields["image_dpi"] = strconv.Itoa(dpi)
    return client
}

// Convert HTML forms to fillable PDF forms. Details can be found in the blog post.
//
// value - Set to true to make fillable PDF forms.
func (client *HtmlToPdfClient) SetEnablePdfForms(value bool) *HtmlToPdfClient {
    client.fields["enable_pdf_forms"] = strconv.FormatBool(value)
    return client
}

// Create linearized PDF. This is also known as Fast Web View.
//
// value - Set to true to create linearized PDF.
func (client *HtmlToPdfClient) SetLinearize(value bool) *HtmlToPdfClient {
    client.fields["linearize"] = strconv.FormatBool(value)
    return client
}

// Encrypt the PDF. This prevents search engines from indexing the contents.
//
// value - Set to true to enable PDF encryption.
func (client *HtmlToPdfClient) SetEncrypt(value bool) *HtmlToPdfClient {
    client.fields["encrypt"] = strconv.FormatBool(value)
    return client
}

// Protect the PDF with a user password. When a PDF has a user password, it must be supplied in order to view the document and to perform operations allowed by the access permissions.
//
// password - The user password.
func (client *HtmlToPdfClient) SetUserPassword(password string) *HtmlToPdfClient {
    client.fields["user_password"] = password
    return client
}

// Protect the PDF with an owner password. Supplying an owner password grants unlimited access to the PDF including changing the passwords and access permissions.
//
// password - The owner password.
func (client *HtmlToPdfClient) SetOwnerPassword(password string) *HtmlToPdfClient {
    client.fields["owner_password"] = password
    return client
}

// Disallow printing of the output PDF.
//
// value - Set to true to set the no-print flag in the output PDF.
func (client *HtmlToPdfClient) SetNoPrint(value bool) *HtmlToPdfClient {
    client.fields["no_print"] = strconv.FormatBool(value)
    return client
}

// Disallow modification of the output PDF.
//
// value - Set to true to set the read-only only flag in the output PDF.
func (client *HtmlToPdfClient) SetNoModify(value bool) *HtmlToPdfClient {
    client.fields["no_modify"] = strconv.FormatBool(value)
    return client
}

// Disallow text and graphics extraction from the output PDF.
//
// value - Set to true to set the no-copy flag in the output PDF.
func (client *HtmlToPdfClient) SetNoCopy(value bool) *HtmlToPdfClient {
    client.fields["no_copy"] = strconv.FormatBool(value)
    return client
}

// Set the title of the PDF.
//
// title - The title.
func (client *HtmlToPdfClient) SetTitle(title string) *HtmlToPdfClient {
    client.fields["title"] = title
    return client
}

// Set the subject of the PDF.
//
// subject - The subject.
func (client *HtmlToPdfClient) SetSubject(subject string) *HtmlToPdfClient {
    client.fields["subject"] = subject
    return client
}

// Set the author of the PDF.
//
// author - The author.
func (client *HtmlToPdfClient) SetAuthor(author string) *HtmlToPdfClient {
    client.fields["author"] = author
    return client
}

// Associate keywords with the document.
//
// keywords - The string with the keywords.
func (client *HtmlToPdfClient) SetKeywords(keywords string) *HtmlToPdfClient {
    client.fields["keywords"] = keywords
    return client
}

// Extract meta tags (author, keywords and description) from the input HTML and use them in the output PDF.
//
// value - Set to true to extract meta tags.
func (client *HtmlToPdfClient) SetExtractMetaTags(value bool) *HtmlToPdfClient {
    client.fields["extract_meta_tags"] = strconv.FormatBool(value)
    return client
}

// Specify the page layout to be used when the document is opened.
//
// layout - Allowed values are single-page, one-column, two-column-left, two-column-right.
func (client *HtmlToPdfClient) SetPageLayout(layout string) *HtmlToPdfClient {
    client.fields["page_layout"] = layout
    return client
}

// Specify how the document should be displayed when opened.
//
// mode - Allowed values are full-screen, thumbnails, outlines.
func (client *HtmlToPdfClient) SetPageMode(mode string) *HtmlToPdfClient {
    client.fields["page_mode"] = mode
    return client
}

// Specify how the page should be displayed when opened.
//
// zoomType - Allowed values are fit-width, fit-height, fit-page.
func (client *HtmlToPdfClient) SetInitialZoomType(zoomType string) *HtmlToPdfClient {
    client.fields["initial_zoom_type"] = zoomType
    return client
}

// Display the specified page when the document is opened.
//
// page - Must be a positive integer.
func (client *HtmlToPdfClient) SetInitialPage(page int) *HtmlToPdfClient {
    client.fields["initial_page"] = strconv.Itoa(page)
    return client
}

// Specify the initial page zoom in percents when the document is opened.
//
// zoom - Must be a positive integer.
func (client *HtmlToPdfClient) SetInitialZoom(zoom int) *HtmlToPdfClient {
    client.fields["initial_zoom"] = strconv.Itoa(zoom)
    return client
}

// Specify whether to hide the viewer application's tool bars when the document is active.
//
// value - Set to true to hide tool bars.
func (client *HtmlToPdfClient) SetHideToolbar(value bool) *HtmlToPdfClient {
    client.fields["hide_toolbar"] = strconv.FormatBool(value)
    return client
}

// Specify whether to hide the viewer application's menu bar when the document is active.
//
// value - Set to true to hide the menu bar.
func (client *HtmlToPdfClient) SetHideMenubar(value bool) *HtmlToPdfClient {
    client.fields["hide_menubar"] = strconv.FormatBool(value)
    return client
}

// Specify whether to hide user interface elements in the document's window (such as scroll bars and navigation controls), leaving only the document's contents displayed.
//
// value - Set to true to hide ui elements.
func (client *HtmlToPdfClient) SetHideWindowUi(value bool) *HtmlToPdfClient {
    client.fields["hide_window_ui"] = strconv.FormatBool(value)
    return client
}

// Specify whether to resize the document's window to fit the size of the first displayed page.
//
// value - Set to true to resize the window.
func (client *HtmlToPdfClient) SetFitWindow(value bool) *HtmlToPdfClient {
    client.fields["fit_window"] = strconv.FormatBool(value)
    return client
}

// Specify whether to position the document's window in the center of the screen.
//
// value - Set to true to center the window.
func (client *HtmlToPdfClient) SetCenterWindow(value bool) *HtmlToPdfClient {
    client.fields["center_window"] = strconv.FormatBool(value)
    return client
}

// Specify whether the window's title bar should display the document title. If false , the title bar should instead display the name of the PDF file containing the document.
//
// value - Set to true to display the title.
func (client *HtmlToPdfClient) SetDisplayTitle(value bool) *HtmlToPdfClient {
    client.fields["display_title"] = strconv.FormatBool(value)
    return client
}

// Set the predominant reading order for text to right-to-left. This option has no direct effect on the document's contents or page numbering but can be used to determine the relative positioning of pages when displayed side by side or printed n-up
//
// value - Set to true to set right-to-left reading order.
func (client *HtmlToPdfClient) SetRightToLeft(value bool) *HtmlToPdfClient {
    client.fields["right_to_left"] = strconv.FormatBool(value)
    return client
}

// Set the input data for template rendering. The data format can be JSON, XML, YAML or CSV.
//
// dataString - The input data string.
func (client *HtmlToPdfClient) SetDataString(dataString string) *HtmlToPdfClient {
    client.fields["data_string"] = dataString
    return client
}

// Load the input data for template rendering from the specified file. The data format can be JSON, XML, YAML or CSV.
//
// dataFile - The file path to a local file containing the input data.
func (client *HtmlToPdfClient) SetDataFile(dataFile string) *HtmlToPdfClient {
    client.files["data_file"] = dataFile
    return client
}

// Specify the input data format.
//
// dataFormat - The data format. Allowed values are auto, json, xml, yaml, csv.
func (client *HtmlToPdfClient) SetDataFormat(dataFormat string) *HtmlToPdfClient {
    client.fields["data_format"] = dataFormat
    return client
}

// Set the encoding of the data file set by setDataFile.
//
// encoding - The data file encoding.
func (client *HtmlToPdfClient) SetDataEncoding(encoding string) *HtmlToPdfClient {
    client.fields["data_encoding"] = encoding
    return client
}

// Ignore undefined variables in the HTML template. The default mode is strict so any undefined variable causes the conversion to fail. You can use {% if variable is defined %} to check if the variable is defined.
//
// value - Set to true to ignore undefined variables.
func (client *HtmlToPdfClient) SetDataIgnoreUndefined(value bool) *HtmlToPdfClient {
    client.fields["data_ignore_undefined"] = strconv.FormatBool(value)
    return client
}

// Auto escape HTML symbols in the input data before placing them into the output.
//
// value - Set to true to turn auto escaping on.
func (client *HtmlToPdfClient) SetDataAutoEscape(value bool) *HtmlToPdfClient {
    client.fields["data_auto_escape"] = strconv.FormatBool(value)
    return client
}

// Auto trim whitespace around each template command block.
//
// value - Set to true to turn auto trimming on.
func (client *HtmlToPdfClient) SetDataTrimBlocks(value bool) *HtmlToPdfClient {
    client.fields["data_trim_blocks"] = strconv.FormatBool(value)
    return client
}

// Set the advanced data options:csv_delimiter - The CSV data delimiter, the default is ,.xml_remove_root - Remove the root XML element from the input data.data_root - The name of the root element inserted into the input data without a root node (e.g. CSV), the default is data.
//
// options - Comma separated list of options.
func (client *HtmlToPdfClient) SetDataOptions(options string) *HtmlToPdfClient {
    client.fields["data_options"] = options
    return client
}

// Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the getDebugLogUrl method or available in conversion statistics.
//
// value - Set to true to enable the debug logging.
func (client *HtmlToPdfClient) SetDebugLog(value bool) *HtmlToPdfClient {
    client.fields["debug_log"] = strconv.FormatBool(value)
    return client
}

// Get the URL of the debug log for the last conversion.
func (client *HtmlToPdfClient) GetDebugLogUrl() string {
    return client.helper.getDebugLogUrl()
}

// Get the number of conversion credits available in your account.
// This method can only be called after a call to one of the convertXtoY methods.
// The returned value can differ from the actual count if you run parallel conversions.
// The special value 999999 is returned if the information is not available.
func (client *HtmlToPdfClient) GetRemainingCreditCount() int {
    return client.helper.getRemainingCreditCount()
}

// Get the number of credits consumed by the last conversion.
func (client *HtmlToPdfClient) GetConsumedCreditCount() int {
    return client.helper.getConsumedCreditCount()
}

// Get the job id.
func (client *HtmlToPdfClient) GetJobId() string {
    return client.helper.getJobId()
}

// Get the number of pages in the output document.
func (client *HtmlToPdfClient) GetPageCount() int {
    return client.helper.getPageCount()
}

// Get the total number of pages in the original output document, including the pages excluded by setPrintPageRange().
func (client *HtmlToPdfClient) GetTotalPageCount() int {
    return client.helper.getTotalPageCount()
}

// Get the size of the output in bytes.
func (client *HtmlToPdfClient) GetOutputSize() int {
    return client.helper.getOutputSize()
}

// Get the version details.
func (client *HtmlToPdfClient) GetVersion() string {
    return fmt.Sprintf("client %s, API v2, converter %s", CLIENT_VERSION, client.helper.getConverterVersion())
}

// Tag the conversion with a custom value. The tag is used in conversion statistics. A value longer than 32 characters is cut off.
//
// tag - A string with the custom tag.
func (client *HtmlToPdfClient) SetTag(tag string) *HtmlToPdfClient {
    client.fields["tag"] = tag
    return client
}

// A proxy server used by the conversion process for accessing the source URLs with HTTP scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
//
// proxy - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
func (client *HtmlToPdfClient) SetHttpProxy(proxy string) *HtmlToPdfClient {
    client.fields["http_proxy"] = proxy
    return client
}

// A proxy server used by the conversion process for accessing the source URLs with HTTPS scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
//
// proxy - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
func (client *HtmlToPdfClient) SetHttpsProxy(proxy string) *HtmlToPdfClient {
    client.fields["https_proxy"] = proxy
    return client
}

// A client certificate to authenticate the converter on your web server. The certificate is used for two-way SSL/TLS authentication and adds extra security.
//
// certificate - The file must be in PKCS12 format. The file must exist and not be empty.
func (client *HtmlToPdfClient) SetClientCertificate(certificate string) *HtmlToPdfClient {
    client.files["client_certificate"] = certificate
    return client
}

// A password for PKCS12 file with a client certificate if it is needed.
//
// password -
func (client *HtmlToPdfClient) SetClientCertificatePassword(password string) *HtmlToPdfClient {
    client.fields["client_certificate_password"] = password
    return client
}

// Set the internal DPI resolution used for positioning of PDF contents. It can help in situations when there are small inaccuracies in the PDF. It is recommended to use values that are a multiple of 72, such as 288 or 360.
//
// dpi - The DPI value. The accepted range is 72-600.
func (client *HtmlToPdfClient) SetLayoutDpi(dpi int) *HtmlToPdfClient {
    client.fields["layout_dpi"] = strconv.Itoa(dpi)
    return client
}

// Set the top left X coordinate of the content area. It is relative to the top left X coordinate of the print area.
//
// x - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'. It may contain a negative value.
func (client *HtmlToPdfClient) SetContentAreaX(x string) *HtmlToPdfClient {
    client.fields["content_area_x"] = x
    return client
}

// Set the top left Y coordinate of the content area. It is relative to the top left Y coordinate of the print area.
//
// y - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'. It may contain a negative value.
func (client *HtmlToPdfClient) SetContentAreaY(y string) *HtmlToPdfClient {
    client.fields["content_area_y"] = y
    return client
}

// Set the width of the content area. It should be at least 1 inch.
//
// width - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *HtmlToPdfClient) SetContentAreaWidth(width string) *HtmlToPdfClient {
    client.fields["content_area_width"] = width
    return client
}

// Set the height of the content area. It should be at least 1 inch.
//
// height - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *HtmlToPdfClient) SetContentAreaHeight(height string) *HtmlToPdfClient {
    client.fields["content_area_height"] = height
    return client
}

// Set the content area position and size. The content area enables to specify a web page area to be converted.
//
// x - Set the top left X coordinate of the content area. It is relative to the top left X coordinate of the print area. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'. It may contain a negative value.
// y - Set the top left Y coordinate of the content area. It is relative to the top left Y coordinate of the print area. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'. It may contain a negative value.
// width - Set the width of the content area. It should be at least 1 inch. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
// height - Set the height of the content area. It should be at least 1 inch. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *HtmlToPdfClient) SetContentArea(x string, y string, width string, height string) *HtmlToPdfClient {
    client.SetContentAreaX(x)
    client.SetContentAreaY(y)
    client.SetContentAreaWidth(width)
    client.SetContentAreaHeight(height)
    return client
}

// A 2D transformation matrix applied to the main contents on each page. The origin [0,0] is located at the top-left corner of the contents. The resolution is 72 dpi.
//
// matrix - A comma separated string of matrix elements: "scaleX,skewX,transX,skewY,scaleY,transY"
func (client *HtmlToPdfClient) SetContentsMatrix(matrix string) *HtmlToPdfClient {
    client.fields["contents_matrix"] = matrix
    return client
}

// A 2D transformation matrix applied to the page header contents. The origin [0,0] is located at the top-left corner of the header. The resolution is 72 dpi.
//
// matrix - A comma separated string of matrix elements: "scaleX,skewX,transX,skewY,scaleY,transY"
func (client *HtmlToPdfClient) SetHeaderMatrix(matrix string) *HtmlToPdfClient {
    client.fields["header_matrix"] = matrix
    return client
}

// A 2D transformation matrix applied to the page footer contents. The origin [0,0] is located at the top-left corner of the footer. The resolution is 72 dpi.
//
// matrix - A comma separated string of matrix elements: "scaleX,skewX,transX,skewY,scaleY,transY"
func (client *HtmlToPdfClient) SetFooterMatrix(matrix string) *HtmlToPdfClient {
    client.fields["footer_matrix"] = matrix
    return client
}

// Disable automatic height adjustment that compensates for pixel to point rounding errors.
//
// value - Set to true to disable automatic height scale.
func (client *HtmlToPdfClient) SetDisablePageHeightOptimization(value bool) *HtmlToPdfClient {
    client.fields["disable_page_height_optimization"] = strconv.FormatBool(value)
    return client
}

// Add special CSS classes to the main document's body element. This allows applying custom styling based on these classes: pdfcrowd-page-X - where X is the current page number pdfcrowd-page-odd - odd page pdfcrowd-page-even - even page
// Warning: If your custom styling affects the contents area size (e.g. by using different margins, padding, border width), the resulting PDF may contain duplicit contents or some contents may be missing.
//
// value - Set to true to add the special CSS classes.
func (client *HtmlToPdfClient) SetMainDocumentCssAnnotation(value bool) *HtmlToPdfClient {
    client.fields["main_document_css_annotation"] = strconv.FormatBool(value)
    return client
}

// Add special CSS classes to the header/footer's body element. This allows applying custom styling based on these classes: pdfcrowd-page-X - where X is the current page number pdfcrowd-page-count-X - where X is the total page count pdfcrowd-page-first - the first page pdfcrowd-page-last - the last page pdfcrowd-page-odd - odd page pdfcrowd-page-even - even page
//
// value - Set to true to add the special CSS classes.
func (client *HtmlToPdfClient) SetHeaderFooterCssAnnotation(value bool) *HtmlToPdfClient {
    client.fields["header_footer_css_annotation"] = strconv.FormatBool(value)
    return client
}

// Set the maximum time to load the page and its resources. After this time, all requests will be considered successful. This can be useful to ensure that the conversion does not timeout. Use this method if there is no other way to fix page loading.
//
// maxTime - The number of seconds to wait. The accepted range is 10-30.
func (client *HtmlToPdfClient) SetMaxLoadingTime(maxTime int) *HtmlToPdfClient {
    client.fields["max_loading_time"] = strconv.Itoa(maxTime)
    return client
}

// Allows to configure conversion via JSON. The configuration defines various page settings for individual PDF pages or ranges of pages. It provides flexibility in designing each page of the PDF, giving control over each page's size, header, footer etc. If a page or parameter is not explicitly specified, the system will use the default settings for that page or attribute. If a JSON configuration is provided, the settings in the JSON will take precedence over the global options. The structure of the JSON must be: pageSetup: An array of objects where each object defines the configuration for a specific page or range of pages. The following properties can be set for each page object: pages: A comma-separated list of page numbers or ranges. Special strings may be used, such as `odd`, `even` and `last`. For example: 1-: from page 1 to the end of the document 2: only the 2nd page 2,4,6: pages 2, 4, and 6 2-5: pages 2 through 5 odd,2: the 2nd page and all odd pages pageSize: The page size (optional). Possible values: A0, A1, A2, A3, A4, A5, A6, Letter. pageWidth: The width of the page (optional). pageHeight: The height of the page (optional). marginLeft: Left margin (optional). marginRight: Right margin (optional). marginTop: Top margin (optional). marginBottom: Bottom margin (optional). displayHeader: Header appearance (optional). Possible values: none: completely excluded space: only the content is excluded, the space is used content: the content is printed (default) displayFooter: Footer appearance (optional). Possible values: none: completely excluded space: only the content is excluded, the space is used content: the content is printed (default) headerHeight: Height of the header (optional). footerHeight: Height of the footer (optional). orientation: Page orientation, such as "portrait" or "landscape" (optional). backgroundColor: Page background color in RRGGBB or RRGGBBAA hexadecimal format (optional). Dimensions may be empty, 0 or specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
//
// jsonString - The JSON string.
func (client *HtmlToPdfClient) SetConversionConfig(jsonString string) *HtmlToPdfClient {
    client.fields["conversion_config"] = jsonString
    return client
}

// Allows to configure the conversion process via JSON file. See details of the JSON string.
//
// filepath - The file path to a local file. The file must exist and not be empty.
func (client *HtmlToPdfClient) SetConversionConfigFile(filepath string) *HtmlToPdfClient {
    client.files["conversion_config_file"] = filepath
    return client
}


func (client *HtmlToPdfClient) SetSubprocessReferrer(referrer string) *HtmlToPdfClient {
    client.fields["subprocess_referrer"] = referrer
    return client
}

// Specifies the User-Agent HTTP header that will be used by the converter when a request is made to the converted web page.
//
// agent - The user agent.
func (client *HtmlToPdfClient) SetConverterUserAgent(agent string) *HtmlToPdfClient {
    client.fields["converter_user_agent"] = agent
    return client
}

// Set the converter version. Different versions may produce different output. Choose which one provides the best output for your case.
//
// version - The version identifier. Allowed values are 24.04, 20.10, 18.10, latest.
func (client *HtmlToPdfClient) SetConverterVersion(version string) *HtmlToPdfClient {
    client.helper.setConverterVersion(version)
    return client
}

// Specify whether to use HTTP or HTTPS when connecting to the PDFCrowd API.
// Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
//
// value - Set to true to use HTTP.
func (client *HtmlToPdfClient) SetUseHttp(value bool) *HtmlToPdfClient {
    client.helper.setUseHttp(value)
    return client
}

// Specifies the User-Agent HTTP header that the client library will use when interacting with the API.
//
// agent - The user agent string.
func (client *HtmlToPdfClient) SetClientUserAgent(agent string) *HtmlToPdfClient {
    client.helper.setUserAgent(agent)
    return client
}

// Set a custom user agent HTTP header. It can be useful if you are behind a proxy or a firewall.
//
// agent - The user agent string.
func (client *HtmlToPdfClient) SetUserAgent(agent string) *HtmlToPdfClient {
    client.helper.setUserAgent(agent)
    return client
}

// Specifies an HTTP proxy that the API client library will use to connect to the internet.
//
// host - The proxy hostname.
// port - The proxy port.
// userName - The username.
// password - The password.
func (client *HtmlToPdfClient) SetProxy(host string, port int, userName string, password string) *HtmlToPdfClient {
    client.helper.setProxy(host, port, userName, password)
    return client
}

// Specifies the number of automatic retries when the 502 or 503 HTTP status code is received. The status code indicates a temporary network issue. This feature can be disabled by setting to 0.
//
// count - Number of retries.
func (client *HtmlToPdfClient) SetRetryCount(count int) *HtmlToPdfClient {
    client.helper.setRetryCount(count)
    return client
}

// Conversion from HTML to image.
type HtmlToImageClient struct {
    helper connectionHelper
    fields map[string]string
    files map[string]string
    rawData map[string][]byte
    fileId int
}

// Constructor for the PDFCrowd API client.
//
// userName - Your username at PDFCrowd.
// apiKey - Your API key.
func NewHtmlToImageClient(userName string, apiKey string) HtmlToImageClient {
    helper := newConnectionHelper(userName, apiKey)
    fields := map[string]string{
        "input_format": "html",
        "output_format": "png",
    }
    return HtmlToImageClient{ helper, fields, make(map[string]string), make(map[string][]byte), 1}
}

// The format of the output file.
//
// outputFormat - Allowed values are png, jpg, gif, tiff, bmp, ico, ppm, pgm, pbm, pnm, psb, pct, ras, tga, sgi, sun, webp.
func (client *HtmlToImageClient) SetOutputFormat(outputFormat string) *HtmlToImageClient {
    client.fields["output_format"] = outputFormat
    return client
}

// Convert a web page.
//
// url - The address of the web page to convert. Supported protocols are http:// and https://.
func (client *HtmlToImageClient) ConvertUrl(url string) ([]byte, error) {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return nil, NewError(createInvalidValueMessage(url, "ConvertUrl", "html-to-image", "Supported protocols are http:// and https://.", "convert_url"), 470)
    }
    
    client.fields["url"] = url
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert a web page and write the result to an output stream.
//
// url - The address of the web page to convert. Supported protocols are http:// and https://.
// outStream - The output stream that will contain the conversion output.
func (client *HtmlToImageClient) ConvertUrlToStream(url string, outStream io.Writer) error {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return NewError(createInvalidValueMessage(url, "ConvertUrlToStream::url", "html-to-image", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470)
    }
    
    client.fields["url"] = url
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert a web page and write the result to a local file.
//
// url - The address of the web page to convert. Supported protocols are http:// and https://.
// filePath - The output file path. The string must not be empty.
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

// Convert a local file.
//
// file - The path to a local file to convert. The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). If the HTML document refers to local external assets (images, style sheets, javascript), zip the document together with the assets. The file must exist and not be empty. The file name must have a valid extension.
func (client *HtmlToImageClient) ConvertFile(file string) ([]byte, error) {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return nil, NewError(createInvalidValueMessage(file, "ConvertFile", "html-to-image", "The file must exist and not be empty.", "convert_file"), 470)
    }
    
    client.files["file"] = file
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert a local file and write the result to an output stream.
//
// file - The path to a local file to convert. The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). If the HTML document refers to local external assets (images, style sheets, javascript), zip the document together with the assets. The file must exist and not be empty. The file name must have a valid extension.
// outStream - The output stream that will contain the conversion output.
func (client *HtmlToImageClient) ConvertFileToStream(file string, outStream io.Writer) error {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return NewError(createInvalidValueMessage(file, "ConvertFileToStream::file", "html-to-image", "The file must exist and not be empty.", "convert_file_to_stream"), 470)
    }
    
    client.files["file"] = file
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert a local file and write the result to a local file.
//
// file - The path to a local file to convert. The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). If the HTML document refers to local external assets (images, style sheets, javascript), zip the document together with the assets. The file must exist and not be empty. The file name must have a valid extension.
// filePath - The output file path. The string must not be empty.
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

// Convert a string.
//
// text - The string content to convert. The string must not be empty.
func (client *HtmlToImageClient) ConvertString(text string) ([]byte, error) {
    if len(text) == 0 {
        return nil, NewError(createInvalidValueMessage(text, "ConvertString", "html-to-image", "The string must not be empty.", "convert_string"), 470)
    }
    
    client.fields["text"] = text
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert a string and write the output to an output stream.
//
// text - The string content to convert. The string must not be empty.
// outStream - The output stream that will contain the conversion output.
func (client *HtmlToImageClient) ConvertStringToStream(text string, outStream io.Writer) error {
    if len(text) == 0 {
        return NewError(createInvalidValueMessage(text, "ConvertStringToStream::text", "html-to-image", "The string must not be empty.", "convert_string_to_stream"), 470)
    }
    
    client.fields["text"] = text
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert a string and write the output to a file.
//
// text - The string content to convert. The string must not be empty.
// filePath - The output file path. The string must not be empty.
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

// Convert the contents of an input stream.
//
// inStream - The input stream with source data. The stream can contain either HTML code or an archive (.zip, .tar.gz, .tar.bz2).The archive can contain HTML code and its external assets (images, style sheets, javascript).
func (client *HtmlToImageClient) ConvertStream(inStream io.Reader) ([]byte, error) {
    data, errRead := ioutil.ReadAll(inStream)
    if errRead != nil {
        return nil, errRead
    }

    client.rawData["stream"] = data
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert the contents of an input stream and write the result to an output stream.
//
// inStream - The input stream with source data. The stream can contain either HTML code or an archive (.zip, .tar.gz, .tar.bz2).The archive can contain HTML code and its external assets (images, style sheets, javascript).
// outStream - The output stream that will contain the conversion output.
func (client *HtmlToImageClient) ConvertStreamToStream(inStream io.Reader, outStream io.Writer) error {
    data, errRead := ioutil.ReadAll(inStream)
    if errRead != nil {
        return errRead
    }

    client.rawData["stream"] = data
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert the contents of an input stream and write the result to a local file.
//
// inStream - The input stream with source data. The stream can contain either HTML code or an archive (.zip, .tar.gz, .tar.bz2).The archive can contain HTML code and its external assets (images, style sheets, javascript).
// filePath - The output file path. The string must not be empty.
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

// Set the file name of the main HTML document stored in the input archive. If not specified, the first HTML file in the archive is used for conversion. Use this method if the input archive contains multiple HTML documents.
//
// filename - The file name.
func (client *HtmlToImageClient) SetZipMainFilename(filename string) *HtmlToImageClient {
    client.fields["zip_main_filename"] = filename
    return client
}

// Set the output image width in pixels.
//
// width - The accepted range is 96-65000.
func (client *HtmlToImageClient) SetScreenshotWidth(width int) *HtmlToImageClient {
    client.fields["screenshot_width"] = strconv.Itoa(width)
    return client
}

// Set the output image height in pixels. If it is not specified, actual document height is used.
//
// height - Must be a positive integer.
func (client *HtmlToImageClient) SetScreenshotHeight(height int) *HtmlToImageClient {
    client.fields["screenshot_height"] = strconv.Itoa(height)
    return client
}

// Set the scaling factor (zoom) for the output image.
//
// factor - The percentage value. Must be a positive integer.
func (client *HtmlToImageClient) SetScaleFactor(factor int) *HtmlToImageClient {
    client.fields["scale_factor"] = strconv.Itoa(factor)
    return client
}

// The output image background color.
//
// color - The value must be in RRGGBB or RRGGBBAA hexadecimal format.
func (client *HtmlToImageClient) SetBackgroundColor(color string) *HtmlToImageClient {
    client.fields["background_color"] = color
    return client
}

// Use the print version of the page if available (@media print).
//
// value - Set to true to use the print version of the page.
func (client *HtmlToImageClient) SetUsePrintMedia(value bool) *HtmlToImageClient {
    client.fields["use_print_media"] = strconv.FormatBool(value)
    return client
}

// Do not print the background graphics.
//
// value - Set to true to disable the background graphics.
func (client *HtmlToImageClient) SetNoBackground(value bool) *HtmlToImageClient {
    client.fields["no_background"] = strconv.FormatBool(value)
    return client
}

// Do not execute JavaScript.
//
// value - Set to true to disable JavaScript in web pages.
func (client *HtmlToImageClient) SetDisableJavascript(value bool) *HtmlToImageClient {
    client.fields["disable_javascript"] = strconv.FormatBool(value)
    return client
}

// Do not load images.
//
// value - Set to true to disable loading of images.
func (client *HtmlToImageClient) SetDisableImageLoading(value bool) *HtmlToImageClient {
    client.fields["disable_image_loading"] = strconv.FormatBool(value)
    return client
}

// Disable loading fonts from remote sources.
//
// value - Set to true disable loading remote fonts.
func (client *HtmlToImageClient) SetDisableRemoteFonts(value bool) *HtmlToImageClient {
    client.fields["disable_remote_fonts"] = strconv.FormatBool(value)
    return client
}

// Use a mobile user agent.
//
// value - Set to true to use a mobile user agent.
func (client *HtmlToImageClient) SetUseMobileUserAgent(value bool) *HtmlToImageClient {
    client.fields["use_mobile_user_agent"] = strconv.FormatBool(value)
    return client
}

// Specifies how iframes are handled.
//
// iframes - Allowed values are all, same-origin, none.
func (client *HtmlToImageClient) SetLoadIframes(iframes string) *HtmlToImageClient {
    client.fields["load_iframes"] = iframes
    return client
}

// Try to block ads. Enabling this option can produce smaller output and speed up the conversion.
//
// value - Set to true to block ads in web pages.
func (client *HtmlToImageClient) SetBlockAds(value bool) *HtmlToImageClient {
    client.fields["block_ads"] = strconv.FormatBool(value)
    return client
}

// Set the default HTML content text encoding.
//
// encoding - The text encoding of the HTML content.
func (client *HtmlToImageClient) SetDefaultEncoding(encoding string) *HtmlToImageClient {
    client.fields["default_encoding"] = encoding
    return client
}

// Set the locale for the conversion. This may affect the output format of dates, times and numbers.
//
// locale - The locale code according to ISO 639.
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

// Set credentials to access HTTP base authentication protected websites.
//
// userName - Set the HTTP authentication user name.
// password - Set the HTTP authentication password.
func (client *HtmlToImageClient) SetHttpAuth(userName string, password string) *HtmlToImageClient {
    client.SetHttpAuthUserName(userName)
    client.SetHttpAuthPassword(password)
    return client
}

// Set HTTP cookies to be included in all requests made by the converter.
//
// cookies - The cookie string.
func (client *HtmlToImageClient) SetCookies(cookies string) *HtmlToImageClient {
    client.fields["cookies"] = cookies
    return client
}

// Do not allow insecure HTTPS connections.
//
// value - Set to true to enable SSL certificate verification.
func (client *HtmlToImageClient) SetVerifySslCertificates(value bool) *HtmlToImageClient {
    client.fields["verify_ssl_certificates"] = strconv.FormatBool(value)
    return client
}

// Abort the conversion if the main URL HTTP status code is greater than or equal to 400.
//
// failOnError - Set to true to abort the conversion.
func (client *HtmlToImageClient) SetFailOnMainUrlError(failOnError bool) *HtmlToImageClient {
    client.fields["fail_on_main_url_error"] = strconv.FormatBool(failOnError)
    return client
}

// Abort the conversion if any of the sub-request HTTP status code is greater than or equal to 400 or if some sub-requests are still pending. See details in a debug log.
//
// failOnError - Set to true to abort the conversion.
func (client *HtmlToImageClient) SetFailOnAnyUrlError(failOnError bool) *HtmlToImageClient {
    client.fields["fail_on_any_url_error"] = strconv.FormatBool(failOnError)
    return client
}

// Do not send the X-Pdfcrowd HTTP header in PDFCrowd HTTP requests.
//
// value - Set to true to disable sending X-Pdfcrowd HTTP header.
func (client *HtmlToImageClient) SetNoXpdfcrowdHeader(value bool) *HtmlToImageClient {
    client.fields["no_xpdfcrowd_header"] = strconv.FormatBool(value)
    return client
}

// Apply custom CSS to the input HTML document. It allows you to modify the visual appearance and layout of your HTML content dynamically. Tip: Using !important in custom CSS provides a way to prioritize and override conflicting styles.
//
// css - A string containing valid CSS. The string must not be empty.
func (client *HtmlToImageClient) SetCustomCss(css string) *HtmlToImageClient {
    client.fields["custom_css"] = css
    return client
}

// Run a custom JavaScript after the document is loaded and ready to print. The script is intended for post-load DOM manipulation (add/remove elements, update CSS, ...). In addition to the standard browser APIs, the custom JavaScript code can use helper functions from our JavaScript library.
//
// javascript - A string containing a JavaScript code. The string must not be empty.
func (client *HtmlToImageClient) SetCustomJavascript(javascript string) *HtmlToImageClient {
    client.fields["custom_javascript"] = javascript
    return client
}

// Run a custom JavaScript right after the document is loaded. The script is intended for early DOM manipulation (add/remove elements, update CSS, ...). In addition to the standard browser APIs, the custom JavaScript code can use helper functions from our JavaScript library.
//
// javascript - A string containing a JavaScript code. The string must not be empty.
func (client *HtmlToImageClient) SetOnLoadJavascript(javascript string) *HtmlToImageClient {
    client.fields["on_load_javascript"] = javascript
    return client
}

// Set a custom HTTP header to be included in all requests made by the converter.
//
// header - A string containing the header name and value separated by a colon.
func (client *HtmlToImageClient) SetCustomHttpHeader(header string) *HtmlToImageClient {
    client.fields["custom_http_header"] = header
    return client
}

// Wait the specified number of milliseconds to finish all JavaScript after the document is loaded. Your license defines the maximum wait time by "Max Delay" parameter.
//
// delay - The number of milliseconds to wait. Must be a positive integer or 0.
func (client *HtmlToImageClient) SetJavascriptDelay(delay int) *HtmlToImageClient {
    client.fields["javascript_delay"] = strconv.Itoa(delay)
    return client
}

// Convert only the specified element from the main document and its children. The element is specified by one or more CSS selectors. If the element is not found, the conversion fails. If multiple elements are found, the first one is used.
//
// selectors - One or more CSS selectors separated by commas. The string must not be empty.
func (client *HtmlToImageClient) SetElementToConvert(selectors string) *HtmlToImageClient {
    client.fields["element_to_convert"] = selectors
    return client
}

// Specify the DOM handling when only a part of the document is converted. This can affect the CSS rules used.
//
// mode - Allowed values are cut-out, remove-siblings, hide-siblings.
func (client *HtmlToImageClient) SetElementToConvertMode(mode string) *HtmlToImageClient {
    client.fields["element_to_convert_mode"] = mode
    return client
}

// Wait for the specified element in a source document. The element is specified by one or more CSS selectors. The element is searched for in the main document and all iframes. If the element is not found, the conversion fails. Your license defines the maximum wait time by "Max Delay" parameter.
//
// selectors - One or more CSS selectors separated by commas. The string must not be empty.
func (client *HtmlToImageClient) SetWaitForElement(selectors string) *HtmlToImageClient {
    client.fields["wait_for_element"] = selectors
    return client
}

// The main HTML element for conversion is detected automatically.
//
// value - Set to true to detect the main element.
func (client *HtmlToImageClient) SetAutoDetectElementToConvert(value bool) *HtmlToImageClient {
    client.fields["auto_detect_element_to_convert"] = strconv.FormatBool(value)
    return client
}

// The input HTML is automatically enhanced to improve the readability.
//
// enhancements - Allowed values are none, readability-v1, readability-v2, readability-v3, readability-v4.
func (client *HtmlToImageClient) SetReadabilityEnhancements(enhancements string) *HtmlToImageClient {
    client.fields["readability_enhancements"] = enhancements
    return client
}

// Set the input data for template rendering. The data format can be JSON, XML, YAML or CSV.
//
// dataString - The input data string.
func (client *HtmlToImageClient) SetDataString(dataString string) *HtmlToImageClient {
    client.fields["data_string"] = dataString
    return client
}

// Load the input data for template rendering from the specified file. The data format can be JSON, XML, YAML or CSV.
//
// dataFile - The file path to a local file containing the input data.
func (client *HtmlToImageClient) SetDataFile(dataFile string) *HtmlToImageClient {
    client.files["data_file"] = dataFile
    return client
}

// Specify the input data format.
//
// dataFormat - The data format. Allowed values are auto, json, xml, yaml, csv.
func (client *HtmlToImageClient) SetDataFormat(dataFormat string) *HtmlToImageClient {
    client.fields["data_format"] = dataFormat
    return client
}

// Set the encoding of the data file set by setDataFile.
//
// encoding - The data file encoding.
func (client *HtmlToImageClient) SetDataEncoding(encoding string) *HtmlToImageClient {
    client.fields["data_encoding"] = encoding
    return client
}

// Ignore undefined variables in the HTML template. The default mode is strict so any undefined variable causes the conversion to fail. You can use {% if variable is defined %} to check if the variable is defined.
//
// value - Set to true to ignore undefined variables.
func (client *HtmlToImageClient) SetDataIgnoreUndefined(value bool) *HtmlToImageClient {
    client.fields["data_ignore_undefined"] = strconv.FormatBool(value)
    return client
}

// Auto escape HTML symbols in the input data before placing them into the output.
//
// value - Set to true to turn auto escaping on.
func (client *HtmlToImageClient) SetDataAutoEscape(value bool) *HtmlToImageClient {
    client.fields["data_auto_escape"] = strconv.FormatBool(value)
    return client
}

// Auto trim whitespace around each template command block.
//
// value - Set to true to turn auto trimming on.
func (client *HtmlToImageClient) SetDataTrimBlocks(value bool) *HtmlToImageClient {
    client.fields["data_trim_blocks"] = strconv.FormatBool(value)
    return client
}

// Set the advanced data options:csv_delimiter - The CSV data delimiter, the default is ,.xml_remove_root - Remove the root XML element from the input data.data_root - The name of the root element inserted into the input data without a root node (e.g. CSV), the default is data.
//
// options - Comma separated list of options.
func (client *HtmlToImageClient) SetDataOptions(options string) *HtmlToImageClient {
    client.fields["data_options"] = options
    return client
}

// Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the getDebugLogUrl method or available in conversion statistics.
//
// value - Set to true to enable the debug logging.
func (client *HtmlToImageClient) SetDebugLog(value bool) *HtmlToImageClient {
    client.fields["debug_log"] = strconv.FormatBool(value)
    return client
}

// Get the URL of the debug log for the last conversion.
func (client *HtmlToImageClient) GetDebugLogUrl() string {
    return client.helper.getDebugLogUrl()
}

// Get the number of conversion credits available in your account.
// This method can only be called after a call to one of the convertXtoY methods.
// The returned value can differ from the actual count if you run parallel conversions.
// The special value 999999 is returned if the information is not available.
func (client *HtmlToImageClient) GetRemainingCreditCount() int {
    return client.helper.getRemainingCreditCount()
}

// Get the number of credits consumed by the last conversion.
func (client *HtmlToImageClient) GetConsumedCreditCount() int {
    return client.helper.getConsumedCreditCount()
}

// Get the job id.
func (client *HtmlToImageClient) GetJobId() string {
    return client.helper.getJobId()
}

// Get the size of the output in bytes.
func (client *HtmlToImageClient) GetOutputSize() int {
    return client.helper.getOutputSize()
}

// Get the version details.
func (client *HtmlToImageClient) GetVersion() string {
    return fmt.Sprintf("client %s, API v2, converter %s", CLIENT_VERSION, client.helper.getConverterVersion())
}

// Tag the conversion with a custom value. The tag is used in conversion statistics. A value longer than 32 characters is cut off.
//
// tag - A string with the custom tag.
func (client *HtmlToImageClient) SetTag(tag string) *HtmlToImageClient {
    client.fields["tag"] = tag
    return client
}

// A proxy server used by the conversion process for accessing the source URLs with HTTP scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
//
// proxy - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
func (client *HtmlToImageClient) SetHttpProxy(proxy string) *HtmlToImageClient {
    client.fields["http_proxy"] = proxy
    return client
}

// A proxy server used by the conversion process for accessing the source URLs with HTTPS scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
//
// proxy - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
func (client *HtmlToImageClient) SetHttpsProxy(proxy string) *HtmlToImageClient {
    client.fields["https_proxy"] = proxy
    return client
}

// A client certificate to authenticate the converter on your web server. The certificate is used for two-way SSL/TLS authentication and adds extra security.
//
// certificate - The file must be in PKCS12 format. The file must exist and not be empty.
func (client *HtmlToImageClient) SetClientCertificate(certificate string) *HtmlToImageClient {
    client.files["client_certificate"] = certificate
    return client
}

// A password for PKCS12 file with a client certificate if it is needed.
//
// password -
func (client *HtmlToImageClient) SetClientCertificatePassword(password string) *HtmlToImageClient {
    client.fields["client_certificate_password"] = password
    return client
}

// Set the maximum time to load the page and its resources. After this time, all requests will be considered successful. This can be useful to ensure that the conversion does not timeout. Use this method if there is no other way to fix page loading.
//
// maxTime - The number of seconds to wait. The accepted range is 10-30.
func (client *HtmlToImageClient) SetMaxLoadingTime(maxTime int) *HtmlToImageClient {
    client.fields["max_loading_time"] = strconv.Itoa(maxTime)
    return client
}


func (client *HtmlToImageClient) SetSubprocessReferrer(referrer string) *HtmlToImageClient {
    client.fields["subprocess_referrer"] = referrer
    return client
}

// Specifies the User-Agent HTTP header that will be used by the converter when a request is made to the converted web page.
//
// agent - The user agent.
func (client *HtmlToImageClient) SetConverterUserAgent(agent string) *HtmlToImageClient {
    client.fields["converter_user_agent"] = agent
    return client
}

// Set the converter version. Different versions may produce different output. Choose which one provides the best output for your case.
//
// version - The version identifier. Allowed values are 24.04, 20.10, 18.10, latest.
func (client *HtmlToImageClient) SetConverterVersion(version string) *HtmlToImageClient {
    client.helper.setConverterVersion(version)
    return client
}

// Specify whether to use HTTP or HTTPS when connecting to the PDFCrowd API.
// Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
//
// value - Set to true to use HTTP.
func (client *HtmlToImageClient) SetUseHttp(value bool) *HtmlToImageClient {
    client.helper.setUseHttp(value)
    return client
}

// Specifies the User-Agent HTTP header that the client library will use when interacting with the API.
//
// agent - The user agent string.
func (client *HtmlToImageClient) SetClientUserAgent(agent string) *HtmlToImageClient {
    client.helper.setUserAgent(agent)
    return client
}

// Set a custom user agent HTTP header. It can be useful if you are behind a proxy or a firewall.
//
// agent - The user agent string.
func (client *HtmlToImageClient) SetUserAgent(agent string) *HtmlToImageClient {
    client.helper.setUserAgent(agent)
    return client
}

// Specifies an HTTP proxy that the API client library will use to connect to the internet.
//
// host - The proxy hostname.
// port - The proxy port.
// userName - The username.
// password - The password.
func (client *HtmlToImageClient) SetProxy(host string, port int, userName string, password string) *HtmlToImageClient {
    client.helper.setProxy(host, port, userName, password)
    return client
}

// Specifies the number of automatic retries when the 502 or 503 HTTP status code is received. The status code indicates a temporary network issue. This feature can be disabled by setting to 0.
//
// count - Number of retries.
func (client *HtmlToImageClient) SetRetryCount(count int) *HtmlToImageClient {
    client.helper.setRetryCount(count)
    return client
}

// Conversion from one image format to another image format.
type ImageToImageClient struct {
    helper connectionHelper
    fields map[string]string
    files map[string]string
    rawData map[string][]byte
    fileId int
}

// Constructor for the PDFCrowd API client.
//
// userName - Your username at PDFCrowd.
// apiKey - Your API key.
func NewImageToImageClient(userName string, apiKey string) ImageToImageClient {
    helper := newConnectionHelper(userName, apiKey)
    fields := map[string]string{
        "input_format": "image",
        "output_format": "png",
    }
    return ImageToImageClient{ helper, fields, make(map[string]string), make(map[string][]byte), 1}
}

// Convert an image.
//
// url - The address of the image to convert. Supported protocols are http:// and https://.
func (client *ImageToImageClient) ConvertUrl(url string) ([]byte, error) {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return nil, NewError(createInvalidValueMessage(url, "ConvertUrl", "image-to-image", "Supported protocols are http:// and https://.", "convert_url"), 470)
    }
    
    client.fields["url"] = url
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert an image and write the result to an output stream.
//
// url - The address of the image to convert. Supported protocols are http:// and https://.
// outStream - The output stream that will contain the conversion output.
func (client *ImageToImageClient) ConvertUrlToStream(url string, outStream io.Writer) error {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return NewError(createInvalidValueMessage(url, "ConvertUrlToStream::url", "image-to-image", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470)
    }
    
    client.fields["url"] = url
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert an image and write the result to a local file.
//
// url - The address of the image to convert. Supported protocols are http:// and https://.
// filePath - The output file path. The string must not be empty.
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

// Convert a local file.
//
// file - The path to a local file to convert. The file must exist and not be empty.
func (client *ImageToImageClient) ConvertFile(file string) ([]byte, error) {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return nil, NewError(createInvalidValueMessage(file, "ConvertFile", "image-to-image", "The file must exist and not be empty.", "convert_file"), 470)
    }
    
    client.files["file"] = file
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert a local file and write the result to an output stream.
//
// file - The path to a local file to convert. The file must exist and not be empty.
// outStream - The output stream that will contain the conversion output.
func (client *ImageToImageClient) ConvertFileToStream(file string, outStream io.Writer) error {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return NewError(createInvalidValueMessage(file, "ConvertFileToStream::file", "image-to-image", "The file must exist and not be empty.", "convert_file_to_stream"), 470)
    }
    
    client.files["file"] = file
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert a local file and write the result to a local file.
//
// file - The path to a local file to convert. The file must exist and not be empty.
// filePath - The output file path. The string must not be empty.
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

// Convert raw data.
//
// data - The raw content to be converted.
func (client *ImageToImageClient) ConvertRawData(data []byte) ([]byte, error) {
    client.rawData["file"] = data
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert raw data and write the result to an output stream.
//
// data - The raw content to be converted.
// outStream - The output stream that will contain the conversion output.
func (client *ImageToImageClient) ConvertRawDataToStream(data []byte, outStream io.Writer) error {
    client.rawData["file"] = data
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert raw data to a file.
//
// data - The raw content to be converted.
// filePath - The output file path. The string must not be empty.
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

// Convert the contents of an input stream.
//
// inStream - The input stream with source data.
func (client *ImageToImageClient) ConvertStream(inStream io.Reader) ([]byte, error) {
    data, errRead := ioutil.ReadAll(inStream)
    if errRead != nil {
        return nil, errRead
    }

    client.rawData["stream"] = data
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert the contents of an input stream and write the result to an output stream.
//
// inStream - The input stream with source data.
// outStream - The output stream that will contain the conversion output.
func (client *ImageToImageClient) ConvertStreamToStream(inStream io.Reader, outStream io.Writer) error {
    data, errRead := ioutil.ReadAll(inStream)
    if errRead != nil {
        return errRead
    }

    client.rawData["stream"] = data
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert the contents of an input stream and write the result to a local file.
//
// inStream - The input stream with source data.
// filePath - The output file path. The string must not be empty.
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

// The format of the output file.
//
// outputFormat - Allowed values are png, jpg, gif, tiff, bmp, ico, ppm, pgm, pbm, pnm, psb, pct, ras, tga, sgi, sun, webp.
func (client *ImageToImageClient) SetOutputFormat(outputFormat string) *ImageToImageClient {
    client.fields["output_format"] = outputFormat
    return client
}

// Resize the image.
//
// resize - The resize percentage or new image dimensions.
func (client *ImageToImageClient) SetResize(resize string) *ImageToImageClient {
    client.fields["resize"] = resize
    return client
}

// Rotate the image.
//
// rotate - The rotation specified in degrees.
func (client *ImageToImageClient) SetRotate(rotate string) *ImageToImageClient {
    client.fields["rotate"] = rotate
    return client
}

// Set the top left X coordinate of the content area. It is relative to the top left X coordinate of the print area.
//
// x - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *ImageToImageClient) SetCropAreaX(x string) *ImageToImageClient {
    client.fields["crop_area_x"] = x
    return client
}

// Set the top left Y coordinate of the content area. It is relative to the top left Y coordinate of the print area.
//
// y - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *ImageToImageClient) SetCropAreaY(y string) *ImageToImageClient {
    client.fields["crop_area_y"] = y
    return client
}

// Set the width of the content area. It should be at least 1 inch.
//
// width - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *ImageToImageClient) SetCropAreaWidth(width string) *ImageToImageClient {
    client.fields["crop_area_width"] = width
    return client
}

// Set the height of the content area. It should be at least 1 inch.
//
// height - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *ImageToImageClient) SetCropAreaHeight(height string) *ImageToImageClient {
    client.fields["crop_area_height"] = height
    return client
}

// Set the content area position and size. The content area enables to specify the part to be converted.
//
// x - Set the top left X coordinate of the content area. It is relative to the top left X coordinate of the print area. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
// y - Set the top left Y coordinate of the content area. It is relative to the top left Y coordinate of the print area. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
// width - Set the width of the content area. It should be at least 1 inch. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
// height - Set the height of the content area. It should be at least 1 inch. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *ImageToImageClient) SetCropArea(x string, y string, width string, height string) *ImageToImageClient {
    client.SetCropAreaX(x)
    client.SetCropAreaY(y)
    client.SetCropAreaWidth(width)
    client.SetCropAreaHeight(height)
    return client
}

// Remove borders of an image which does not change in color.
//
// value - Set to true to remove borders.
func (client *ImageToImageClient) SetRemoveBorders(value bool) *ImageToImageClient {
    client.fields["remove_borders"] = strconv.FormatBool(value)
    return client
}

// Set the output canvas size.
//
// size - Allowed values are A0, A1, A2, A3, A4, A5, A6, Letter.
func (client *ImageToImageClient) SetCanvasSize(size string) *ImageToImageClient {
    client.fields["canvas_size"] = size
    return client
}

// Set the output canvas width.
//
// width - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *ImageToImageClient) SetCanvasWidth(width string) *ImageToImageClient {
    client.fields["canvas_width"] = width
    return client
}

// Set the output canvas height.
//
// height - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *ImageToImageClient) SetCanvasHeight(height string) *ImageToImageClient {
    client.fields["canvas_height"] = height
    return client
}

// Set the output canvas dimensions. If no canvas size is specified, margins are applied as a border around the image.
//
// width - Set the output canvas width. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
// height - Set the output canvas height. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *ImageToImageClient) SetCanvasDimensions(width string, height string) *ImageToImageClient {
    client.SetCanvasWidth(width)
    client.SetCanvasHeight(height)
    return client
}

// Set the output canvas orientation.
//
// orientation - Allowed values are landscape, portrait.
func (client *ImageToImageClient) SetOrientation(orientation string) *ImageToImageClient {
    client.fields["orientation"] = orientation
    return client
}

// Set the image position on the canvas.
//
// position - Allowed values are center, top, bottom, left, right, top-left, top-right, bottom-left, bottom-right.
func (client *ImageToImageClient) SetPosition(position string) *ImageToImageClient {
    client.fields["position"] = position
    return client
}

// Set the mode to print the image on the canvas.
//
// mode - Allowed values are default, fit, stretch.
func (client *ImageToImageClient) SetPrintCanvasMode(mode string) *ImageToImageClient {
    client.fields["print_canvas_mode"] = mode
    return client
}

// Set the output canvas top margin.
//
// top - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *ImageToImageClient) SetMarginTop(top string) *ImageToImageClient {
    client.fields["margin_top"] = top
    return client
}

// Set the output canvas right margin.
//
// right - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *ImageToImageClient) SetMarginRight(right string) *ImageToImageClient {
    client.fields["margin_right"] = right
    return client
}

// Set the output canvas bottom margin.
//
// bottom - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *ImageToImageClient) SetMarginBottom(bottom string) *ImageToImageClient {
    client.fields["margin_bottom"] = bottom
    return client
}

// Set the output canvas left margin.
//
// left - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *ImageToImageClient) SetMarginLeft(left string) *ImageToImageClient {
    client.fields["margin_left"] = left
    return client
}

// Set the output canvas margins.
//
// top - Set the output canvas top margin. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
// right - Set the output canvas right margin. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
// bottom - Set the output canvas bottom margin. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
// left - Set the output canvas left margin. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *ImageToImageClient) SetMargins(top string, right string, bottom string, left string) *ImageToImageClient {
    client.SetMarginTop(top)
    client.SetMarginRight(right)
    client.SetMarginBottom(bottom)
    client.SetMarginLeft(left)
    return client
}

// The canvas background color in RGB or RGBA hexadecimal format. The color fills the entire canvas regardless of margins. If no canvas size is specified and the image format supports background (e.g. PDF, PNG), the background color is applied too.
//
// color - The value must be in RRGGBB or RRGGBBAA hexadecimal format.
func (client *ImageToImageClient) SetCanvasBackgroundColor(color string) *ImageToImageClient {
    client.fields["canvas_background_color"] = color
    return client
}

// Set the DPI resolution of the input image. The DPI affects margin options specified in points too (e.g. 1 point is equal to 1 pixel in 96 DPI).
//
// dpi - The DPI value.
func (client *ImageToImageClient) SetDpi(dpi int) *ImageToImageClient {
    client.fields["dpi"] = strconv.Itoa(dpi)
    return client
}

// Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the getDebugLogUrl method or available in conversion statistics.
//
// value - Set to true to enable the debug logging.
func (client *ImageToImageClient) SetDebugLog(value bool) *ImageToImageClient {
    client.fields["debug_log"] = strconv.FormatBool(value)
    return client
}

// Get the URL of the debug log for the last conversion.
func (client *ImageToImageClient) GetDebugLogUrl() string {
    return client.helper.getDebugLogUrl()
}

// Get the number of conversion credits available in your account.
// This method can only be called after a call to one of the convertXtoY methods.
// The returned value can differ from the actual count if you run parallel conversions.
// The special value 999999 is returned if the information is not available.
func (client *ImageToImageClient) GetRemainingCreditCount() int {
    return client.helper.getRemainingCreditCount()
}

// Get the number of credits consumed by the last conversion.
func (client *ImageToImageClient) GetConsumedCreditCount() int {
    return client.helper.getConsumedCreditCount()
}

// Get the job id.
func (client *ImageToImageClient) GetJobId() string {
    return client.helper.getJobId()
}

// Get the size of the output in bytes.
func (client *ImageToImageClient) GetOutputSize() int {
    return client.helper.getOutputSize()
}

// Get the version details.
func (client *ImageToImageClient) GetVersion() string {
    return fmt.Sprintf("client %s, API v2, converter %s", CLIENT_VERSION, client.helper.getConverterVersion())
}

// Tag the conversion with a custom value. The tag is used in conversion statistics. A value longer than 32 characters is cut off.
//
// tag - A string with the custom tag.
func (client *ImageToImageClient) SetTag(tag string) *ImageToImageClient {
    client.fields["tag"] = tag
    return client
}

// A proxy server used by the conversion process for accessing the source URLs with HTTP scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
//
// proxy - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
func (client *ImageToImageClient) SetHttpProxy(proxy string) *ImageToImageClient {
    client.fields["http_proxy"] = proxy
    return client
}

// A proxy server used by the conversion process for accessing the source URLs with HTTPS scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
//
// proxy - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
func (client *ImageToImageClient) SetHttpsProxy(proxy string) *ImageToImageClient {
    client.fields["https_proxy"] = proxy
    return client
}

// Set the converter version. Different versions may produce different output. Choose which one provides the best output for your case.
//
// version - The version identifier. Allowed values are 24.04, 20.10, 18.10, latest.
func (client *ImageToImageClient) SetConverterVersion(version string) *ImageToImageClient {
    client.helper.setConverterVersion(version)
    return client
}

// Specify whether to use HTTP or HTTPS when connecting to the PDFCrowd API.
// Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
//
// value - Set to true to use HTTP.
func (client *ImageToImageClient) SetUseHttp(value bool) *ImageToImageClient {
    client.helper.setUseHttp(value)
    return client
}

// Specifies the User-Agent HTTP header that the client library will use when interacting with the API.
//
// agent - The user agent string.
func (client *ImageToImageClient) SetClientUserAgent(agent string) *ImageToImageClient {
    client.helper.setUserAgent(agent)
    return client
}

// Set a custom user agent HTTP header. It can be useful if you are behind a proxy or a firewall.
//
// agent - The user agent string.
func (client *ImageToImageClient) SetUserAgent(agent string) *ImageToImageClient {
    client.helper.setUserAgent(agent)
    return client
}

// Specifies an HTTP proxy that the API client library will use to connect to the internet.
//
// host - The proxy hostname.
// port - The proxy port.
// userName - The username.
// password - The password.
func (client *ImageToImageClient) SetProxy(host string, port int, userName string, password string) *ImageToImageClient {
    client.helper.setProxy(host, port, userName, password)
    return client
}

// Specifies the number of automatic retries when the 502 or 503 HTTP status code is received. The status code indicates a temporary network issue. This feature can be disabled by setting to 0.
//
// count - Number of retries.
func (client *ImageToImageClient) SetRetryCount(count int) *ImageToImageClient {
    client.helper.setRetryCount(count)
    return client
}

// Conversion from PDF to PDF.
type PdfToPdfClient struct {
    helper connectionHelper
    fields map[string]string
    files map[string]string
    rawData map[string][]byte
    fileId int
}

// Constructor for the PDFCrowd API client.
//
// userName - Your username at PDFCrowd.
// apiKey - Your API key.
func NewPdfToPdfClient(userName string, apiKey string) PdfToPdfClient {
    helper := newConnectionHelper(userName, apiKey)
    fields := map[string]string{
        "input_format": "pdf",
        "output_format": "pdf",
    }
    return PdfToPdfClient{ helper, fields, make(map[string]string), make(map[string][]byte), 1}
}

// Specifies the action to be performed on the input PDFs.
//
// action - Allowed values are join, shuffle, extract, delete.
func (client *PdfToPdfClient) SetAction(action string) *PdfToPdfClient {
    client.fields["action"] = action
    return client
}

// Perform an action on the input files.
func (client *PdfToPdfClient) Convert() ([]byte, error) {
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Perform an action on the input files and write the output PDF to an output stream.
//
// outStream - The output stream that will contain the output PDF.
func (client *PdfToPdfClient) ConvertToStream(outStream io.Writer) error {
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Perform an action on the input files and write the output PDF to a file.
//
// filePath - The output file path. The string must not be empty.
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

// Add a PDF file to the list of the input PDFs.
//
// filePath - The file path to a local PDF file. The file must exist and not be empty.
func (client *PdfToPdfClient) AddPdfFile(filePath string) *PdfToPdfClient {
    client.files["f_" + strconv.Itoa(client.fileId)] = filePath
    client.fileId++
    return client
}

// Add in-memory raw PDF data to the list of the input PDFs.Typical usage is for adding PDF created by another PDFCrowd converter. Example in PHP: $clientPdf2Pdf->addPdfRawData($clientHtml2Pdf->convertUrl('http://www.example.com'));
//
// data - The raw PDF data. The input data must be PDF content.
func (client *PdfToPdfClient) AddPdfRawData(data []byte) *PdfToPdfClient {
    client.rawData["f_" + strconv.Itoa(client.fileId)] = data
    client.fileId++
    return client
}

// Password to open the encrypted PDF file.
//
// password - The input PDF password.
func (client *PdfToPdfClient) SetInputPdfPassword(password string) *PdfToPdfClient {
    client.fields["input_pdf_password"] = password
    return client
}

// Set the page range for extract or delete action.
//
// pages - A comma separated list of page numbers or ranges.
func (client *PdfToPdfClient) SetPageRange(pages string) *PdfToPdfClient {
    client.fields["page_range"] = pages
    return client
}

// Apply a watermark to each page of the output PDF file. A watermark can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the watermark.
//
// watermark - The file path to a local file. The file must exist and not be empty.
func (client *PdfToPdfClient) SetPageWatermark(watermark string) *PdfToPdfClient {
    client.files["page_watermark"] = watermark
    return client
}

// Load a file from the specified URL and apply the file as a watermark to each page of the output PDF. A watermark can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the watermark.
//
// url - Supported protocols are http:// and https://.
func (client *PdfToPdfClient) SetPageWatermarkUrl(url string) *PdfToPdfClient {
    client.fields["page_watermark_url"] = url
    return client
}

// Apply each page of a watermark to the corresponding page of the output PDF. A watermark can be either a PDF or an image.
//
// watermark - The file path to a local file. The file must exist and not be empty.
func (client *PdfToPdfClient) SetMultipageWatermark(watermark string) *PdfToPdfClient {
    client.files["multipage_watermark"] = watermark
    return client
}

// Load a file from the specified URL and apply each page of the file as a watermark to the corresponding page of the output PDF. A watermark can be either a PDF or an image.
//
// url - Supported protocols are http:// and https://.
func (client *PdfToPdfClient) SetMultipageWatermarkUrl(url string) *PdfToPdfClient {
    client.fields["multipage_watermark_url"] = url
    return client
}

// Apply a background to each page of the output PDF file. A background can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the background.
//
// background - The file path to a local file. The file must exist and not be empty.
func (client *PdfToPdfClient) SetPageBackground(background string) *PdfToPdfClient {
    client.files["page_background"] = background
    return client
}

// Load a file from the specified URL and apply the file as a background to each page of the output PDF. A background can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the background.
//
// url - Supported protocols are http:// and https://.
func (client *PdfToPdfClient) SetPageBackgroundUrl(url string) *PdfToPdfClient {
    client.fields["page_background_url"] = url
    return client
}

// Apply each page of a background to the corresponding page of the output PDF. A background can be either a PDF or an image.
//
// background - The file path to a local file. The file must exist and not be empty.
func (client *PdfToPdfClient) SetMultipageBackground(background string) *PdfToPdfClient {
    client.files["multipage_background"] = background
    return client
}

// Load a file from the specified URL and apply each page of the file as a background to the corresponding page of the output PDF. A background can be either a PDF or an image.
//
// url - Supported protocols are http:// and https://.
func (client *PdfToPdfClient) SetMultipageBackgroundUrl(url string) *PdfToPdfClient {
    client.fields["multipage_background_url"] = url
    return client
}

// Create linearized PDF. This is also known as Fast Web View.
//
// value - Set to true to create linearized PDF.
func (client *PdfToPdfClient) SetLinearize(value bool) *PdfToPdfClient {
    client.fields["linearize"] = strconv.FormatBool(value)
    return client
}

// Encrypt the PDF. This prevents search engines from indexing the contents.
//
// value - Set to true to enable PDF encryption.
func (client *PdfToPdfClient) SetEncrypt(value bool) *PdfToPdfClient {
    client.fields["encrypt"] = strconv.FormatBool(value)
    return client
}

// Protect the PDF with a user password. When a PDF has a user password, it must be supplied in order to view the document and to perform operations allowed by the access permissions.
//
// password - The user password.
func (client *PdfToPdfClient) SetUserPassword(password string) *PdfToPdfClient {
    client.fields["user_password"] = password
    return client
}

// Protect the PDF with an owner password. Supplying an owner password grants unlimited access to the PDF including changing the passwords and access permissions.
//
// password - The owner password.
func (client *PdfToPdfClient) SetOwnerPassword(password string) *PdfToPdfClient {
    client.fields["owner_password"] = password
    return client
}

// Disallow printing of the output PDF.
//
// value - Set to true to set the no-print flag in the output PDF.
func (client *PdfToPdfClient) SetNoPrint(value bool) *PdfToPdfClient {
    client.fields["no_print"] = strconv.FormatBool(value)
    return client
}

// Disallow modification of the output PDF.
//
// value - Set to true to set the read-only only flag in the output PDF.
func (client *PdfToPdfClient) SetNoModify(value bool) *PdfToPdfClient {
    client.fields["no_modify"] = strconv.FormatBool(value)
    return client
}

// Disallow text and graphics extraction from the output PDF.
//
// value - Set to true to set the no-copy flag in the output PDF.
func (client *PdfToPdfClient) SetNoCopy(value bool) *PdfToPdfClient {
    client.fields["no_copy"] = strconv.FormatBool(value)
    return client
}

// Set the title of the PDF.
//
// title - The title.
func (client *PdfToPdfClient) SetTitle(title string) *PdfToPdfClient {
    client.fields["title"] = title
    return client
}

// Set the subject of the PDF.
//
// subject - The subject.
func (client *PdfToPdfClient) SetSubject(subject string) *PdfToPdfClient {
    client.fields["subject"] = subject
    return client
}

// Set the author of the PDF.
//
// author - The author.
func (client *PdfToPdfClient) SetAuthor(author string) *PdfToPdfClient {
    client.fields["author"] = author
    return client
}

// Associate keywords with the document.
//
// keywords - The string with the keywords.
func (client *PdfToPdfClient) SetKeywords(keywords string) *PdfToPdfClient {
    client.fields["keywords"] = keywords
    return client
}

// Use metadata (title, subject, author and keywords) from the n-th input PDF.
//
// index - Set the index of the input PDF file from which to use the metadata. 0 means no metadata. Must be a positive integer or 0.
func (client *PdfToPdfClient) SetUseMetadataFrom(index int) *PdfToPdfClient {
    client.fields["use_metadata_from"] = strconv.Itoa(index)
    return client
}

// Specify the page layout to be used when the document is opened.
//
// layout - Allowed values are single-page, one-column, two-column-left, two-column-right.
func (client *PdfToPdfClient) SetPageLayout(layout string) *PdfToPdfClient {
    client.fields["page_layout"] = layout
    return client
}

// Specify how the document should be displayed when opened.
//
// mode - Allowed values are full-screen, thumbnails, outlines.
func (client *PdfToPdfClient) SetPageMode(mode string) *PdfToPdfClient {
    client.fields["page_mode"] = mode
    return client
}

// Specify how the page should be displayed when opened.
//
// zoomType - Allowed values are fit-width, fit-height, fit-page.
func (client *PdfToPdfClient) SetInitialZoomType(zoomType string) *PdfToPdfClient {
    client.fields["initial_zoom_type"] = zoomType
    return client
}

// Display the specified page when the document is opened.
//
// page - Must be a positive integer.
func (client *PdfToPdfClient) SetInitialPage(page int) *PdfToPdfClient {
    client.fields["initial_page"] = strconv.Itoa(page)
    return client
}

// Specify the initial page zoom in percents when the document is opened.
//
// zoom - Must be a positive integer.
func (client *PdfToPdfClient) SetInitialZoom(zoom int) *PdfToPdfClient {
    client.fields["initial_zoom"] = strconv.Itoa(zoom)
    return client
}

// Specify whether to hide the viewer application's tool bars when the document is active.
//
// value - Set to true to hide tool bars.
func (client *PdfToPdfClient) SetHideToolbar(value bool) *PdfToPdfClient {
    client.fields["hide_toolbar"] = strconv.FormatBool(value)
    return client
}

// Specify whether to hide the viewer application's menu bar when the document is active.
//
// value - Set to true to hide the menu bar.
func (client *PdfToPdfClient) SetHideMenubar(value bool) *PdfToPdfClient {
    client.fields["hide_menubar"] = strconv.FormatBool(value)
    return client
}

// Specify whether to hide user interface elements in the document's window (such as scroll bars and navigation controls), leaving only the document's contents displayed.
//
// value - Set to true to hide ui elements.
func (client *PdfToPdfClient) SetHideWindowUi(value bool) *PdfToPdfClient {
    client.fields["hide_window_ui"] = strconv.FormatBool(value)
    return client
}

// Specify whether to resize the document's window to fit the size of the first displayed page.
//
// value - Set to true to resize the window.
func (client *PdfToPdfClient) SetFitWindow(value bool) *PdfToPdfClient {
    client.fields["fit_window"] = strconv.FormatBool(value)
    return client
}

// Specify whether to position the document's window in the center of the screen.
//
// value - Set to true to center the window.
func (client *PdfToPdfClient) SetCenterWindow(value bool) *PdfToPdfClient {
    client.fields["center_window"] = strconv.FormatBool(value)
    return client
}

// Specify whether the window's title bar should display the document title. If false , the title bar should instead display the name of the PDF file containing the document.
//
// value - Set to true to display the title.
func (client *PdfToPdfClient) SetDisplayTitle(value bool) *PdfToPdfClient {
    client.fields["display_title"] = strconv.FormatBool(value)
    return client
}

// Set the predominant reading order for text to right-to-left. This option has no direct effect on the document's contents or page numbering but can be used to determine the relative positioning of pages when displayed side by side or printed n-up
//
// value - Set to true to set right-to-left reading order.
func (client *PdfToPdfClient) SetRightToLeft(value bool) *PdfToPdfClient {
    client.fields["right_to_left"] = strconv.FormatBool(value)
    return client
}

// Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the getDebugLogUrl method or available in conversion statistics.
//
// value - Set to true to enable the debug logging.
func (client *PdfToPdfClient) SetDebugLog(value bool) *PdfToPdfClient {
    client.fields["debug_log"] = strconv.FormatBool(value)
    return client
}

// Get the URL of the debug log for the last conversion.
func (client *PdfToPdfClient) GetDebugLogUrl() string {
    return client.helper.getDebugLogUrl()
}

// Get the number of conversion credits available in your account.
// This method can only be called after a call to one of the convertXtoY methods.
// The returned value can differ from the actual count if you run parallel conversions.
// The special value 999999 is returned if the information is not available.
func (client *PdfToPdfClient) GetRemainingCreditCount() int {
    return client.helper.getRemainingCreditCount()
}

// Get the number of credits consumed by the last conversion.
func (client *PdfToPdfClient) GetConsumedCreditCount() int {
    return client.helper.getConsumedCreditCount()
}

// Get the job id.
func (client *PdfToPdfClient) GetJobId() string {
    return client.helper.getJobId()
}

// Get the number of pages in the output document.
func (client *PdfToPdfClient) GetPageCount() int {
    return client.helper.getPageCount()
}

// Get the size of the output in bytes.
func (client *PdfToPdfClient) GetOutputSize() int {
    return client.helper.getOutputSize()
}

// Get the version details.
func (client *PdfToPdfClient) GetVersion() string {
    return fmt.Sprintf("client %s, API v2, converter %s", CLIENT_VERSION, client.helper.getConverterVersion())
}

// Tag the conversion with a custom value. The tag is used in conversion statistics. A value longer than 32 characters is cut off.
//
// tag - A string with the custom tag.
func (client *PdfToPdfClient) SetTag(tag string) *PdfToPdfClient {
    client.fields["tag"] = tag
    return client
}

// Set the converter version. Different versions may produce different output. Choose which one provides the best output for your case.
//
// version - The version identifier. Allowed values are 24.04, 20.10, 18.10, latest.
func (client *PdfToPdfClient) SetConverterVersion(version string) *PdfToPdfClient {
    client.helper.setConverterVersion(version)
    return client
}

// Specify whether to use HTTP or HTTPS when connecting to the PDFCrowd API.
// Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
//
// value - Set to true to use HTTP.
func (client *PdfToPdfClient) SetUseHttp(value bool) *PdfToPdfClient {
    client.helper.setUseHttp(value)
    return client
}

// Specifies the User-Agent HTTP header that the client library will use when interacting with the API.
//
// agent - The user agent string.
func (client *PdfToPdfClient) SetClientUserAgent(agent string) *PdfToPdfClient {
    client.helper.setUserAgent(agent)
    return client
}

// Set a custom user agent HTTP header. It can be useful if you are behind a proxy or a firewall.
//
// agent - The user agent string.
func (client *PdfToPdfClient) SetUserAgent(agent string) *PdfToPdfClient {
    client.helper.setUserAgent(agent)
    return client
}

// Specifies an HTTP proxy that the API client library will use to connect to the internet.
//
// host - The proxy hostname.
// port - The proxy port.
// userName - The username.
// password - The password.
func (client *PdfToPdfClient) SetProxy(host string, port int, userName string, password string) *PdfToPdfClient {
    client.helper.setProxy(host, port, userName, password)
    return client
}

// Specifies the number of automatic retries when the 502 or 503 HTTP status code is received. The status code indicates a temporary network issue. This feature can be disabled by setting to 0.
//
// count - Number of retries.
func (client *PdfToPdfClient) SetRetryCount(count int) *PdfToPdfClient {
    client.helper.setRetryCount(count)
    return client
}

// Conversion from an image to PDF.
type ImageToPdfClient struct {
    helper connectionHelper
    fields map[string]string
    files map[string]string
    rawData map[string][]byte
    fileId int
}

// Constructor for the PDFCrowd API client.
//
// userName - Your username at PDFCrowd.
// apiKey - Your API key.
func NewImageToPdfClient(userName string, apiKey string) ImageToPdfClient {
    helper := newConnectionHelper(userName, apiKey)
    fields := map[string]string{
        "input_format": "image",
        "output_format": "pdf",
    }
    return ImageToPdfClient{ helper, fields, make(map[string]string), make(map[string][]byte), 1}
}

// Convert an image.
//
// url - The address of the image to convert. Supported protocols are http:// and https://.
func (client *ImageToPdfClient) ConvertUrl(url string) ([]byte, error) {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return nil, NewError(createInvalidValueMessage(url, "ConvertUrl", "image-to-pdf", "Supported protocols are http:// and https://.", "convert_url"), 470)
    }
    
    client.fields["url"] = url
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert an image and write the result to an output stream.
//
// url - The address of the image to convert. Supported protocols are http:// and https://.
// outStream - The output stream that will contain the conversion output.
func (client *ImageToPdfClient) ConvertUrlToStream(url string, outStream io.Writer) error {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return NewError(createInvalidValueMessage(url, "ConvertUrlToStream::url", "image-to-pdf", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470)
    }
    
    client.fields["url"] = url
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert an image and write the result to a local file.
//
// url - The address of the image to convert. Supported protocols are http:// and https://.
// filePath - The output file path. The string must not be empty.
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

// Convert a local file.
//
// file - The path to a local file to convert. The file must exist and not be empty.
func (client *ImageToPdfClient) ConvertFile(file string) ([]byte, error) {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return nil, NewError(createInvalidValueMessage(file, "ConvertFile", "image-to-pdf", "The file must exist and not be empty.", "convert_file"), 470)
    }
    
    client.files["file"] = file
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert a local file and write the result to an output stream.
//
// file - The path to a local file to convert. The file must exist and not be empty.
// outStream - The output stream that will contain the conversion output.
func (client *ImageToPdfClient) ConvertFileToStream(file string, outStream io.Writer) error {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return NewError(createInvalidValueMessage(file, "ConvertFileToStream::file", "image-to-pdf", "The file must exist and not be empty.", "convert_file_to_stream"), 470)
    }
    
    client.files["file"] = file
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert a local file and write the result to a local file.
//
// file - The path to a local file to convert. The file must exist and not be empty.
// filePath - The output file path. The string must not be empty.
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

// Convert raw data.
//
// data - The raw content to be converted.
func (client *ImageToPdfClient) ConvertRawData(data []byte) ([]byte, error) {
    client.rawData["file"] = data
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert raw data and write the result to an output stream.
//
// data - The raw content to be converted.
// outStream - The output stream that will contain the conversion output.
func (client *ImageToPdfClient) ConvertRawDataToStream(data []byte, outStream io.Writer) error {
    client.rawData["file"] = data
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert raw data to a file.
//
// data - The raw content to be converted.
// filePath - The output file path. The string must not be empty.
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

// Convert the contents of an input stream.
//
// inStream - The input stream with source data.
func (client *ImageToPdfClient) ConvertStream(inStream io.Reader) ([]byte, error) {
    data, errRead := ioutil.ReadAll(inStream)
    if errRead != nil {
        return nil, errRead
    }

    client.rawData["stream"] = data
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert the contents of an input stream and write the result to an output stream.
//
// inStream - The input stream with source data.
// outStream - The output stream that will contain the conversion output.
func (client *ImageToPdfClient) ConvertStreamToStream(inStream io.Reader, outStream io.Writer) error {
    data, errRead := ioutil.ReadAll(inStream)
    if errRead != nil {
        return errRead
    }

    client.rawData["stream"] = data
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert the contents of an input stream and write the result to a local file.
//
// inStream - The input stream with source data.
// filePath - The output file path. The string must not be empty.
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

// Resize the image.
//
// resize - The resize percentage or new image dimensions.
func (client *ImageToPdfClient) SetResize(resize string) *ImageToPdfClient {
    client.fields["resize"] = resize
    return client
}

// Rotate the image.
//
// rotate - The rotation specified in degrees.
func (client *ImageToPdfClient) SetRotate(rotate string) *ImageToPdfClient {
    client.fields["rotate"] = rotate
    return client
}

// Set the top left X coordinate of the content area. It is relative to the top left X coordinate of the print area.
//
// x - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *ImageToPdfClient) SetCropAreaX(x string) *ImageToPdfClient {
    client.fields["crop_area_x"] = x
    return client
}

// Set the top left Y coordinate of the content area. It is relative to the top left Y coordinate of the print area.
//
// y - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *ImageToPdfClient) SetCropAreaY(y string) *ImageToPdfClient {
    client.fields["crop_area_y"] = y
    return client
}

// Set the width of the content area. It should be at least 1 inch.
//
// width - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *ImageToPdfClient) SetCropAreaWidth(width string) *ImageToPdfClient {
    client.fields["crop_area_width"] = width
    return client
}

// Set the height of the content area. It should be at least 1 inch.
//
// height - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *ImageToPdfClient) SetCropAreaHeight(height string) *ImageToPdfClient {
    client.fields["crop_area_height"] = height
    return client
}

// Set the content area position and size. The content area enables to specify the part to be converted.
//
// x - Set the top left X coordinate of the content area. It is relative to the top left X coordinate of the print area. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
// y - Set the top left Y coordinate of the content area. It is relative to the top left Y coordinate of the print area. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
// width - Set the width of the content area. It should be at least 1 inch. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
// height - Set the height of the content area. It should be at least 1 inch. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *ImageToPdfClient) SetCropArea(x string, y string, width string, height string) *ImageToPdfClient {
    client.SetCropAreaX(x)
    client.SetCropAreaY(y)
    client.SetCropAreaWidth(width)
    client.SetCropAreaHeight(height)
    return client
}

// Remove borders of an image which does not change in color.
//
// value - Set to true to remove borders.
func (client *ImageToPdfClient) SetRemoveBorders(value bool) *ImageToPdfClient {
    client.fields["remove_borders"] = strconv.FormatBool(value)
    return client
}

// Set the output page size.
//
// size - Allowed values are A0, A1, A2, A3, A4, A5, A6, Letter.
func (client *ImageToPdfClient) SetPageSize(size string) *ImageToPdfClient {
    client.fields["page_size"] = size
    return client
}

// Set the output page width.
//
// width - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *ImageToPdfClient) SetPageWidth(width string) *ImageToPdfClient {
    client.fields["page_width"] = width
    return client
}

// Set the output page height.
//
// height - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *ImageToPdfClient) SetPageHeight(height string) *ImageToPdfClient {
    client.fields["page_height"] = height
    return client
}

// Set the output page dimensions. If no page size is specified, margins are applied as a border around the image.
//
// width - Set the output page width. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
// height - Set the output page height. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *ImageToPdfClient) SetPageDimensions(width string, height string) *ImageToPdfClient {
    client.SetPageWidth(width)
    client.SetPageHeight(height)
    return client
}

// Set the output page orientation.
//
// orientation - Allowed values are landscape, portrait.
func (client *ImageToPdfClient) SetOrientation(orientation string) *ImageToPdfClient {
    client.fields["orientation"] = orientation
    return client
}

// Set the image position on the page.
//
// position - Allowed values are center, top, bottom, left, right, top-left, top-right, bottom-left, bottom-right.
func (client *ImageToPdfClient) SetPosition(position string) *ImageToPdfClient {
    client.fields["position"] = position
    return client
}

// Set the mode to print the image on the content area of the page.
//
// mode - Allowed values are default, fit, stretch.
func (client *ImageToPdfClient) SetPrintPageMode(mode string) *ImageToPdfClient {
    client.fields["print_page_mode"] = mode
    return client
}

// Set the output page top margin.
//
// top - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *ImageToPdfClient) SetMarginTop(top string) *ImageToPdfClient {
    client.fields["margin_top"] = top
    return client
}

// Set the output page right margin.
//
// right - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *ImageToPdfClient) SetMarginRight(right string) *ImageToPdfClient {
    client.fields["margin_right"] = right
    return client
}

// Set the output page bottom margin.
//
// bottom - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *ImageToPdfClient) SetMarginBottom(bottom string) *ImageToPdfClient {
    client.fields["margin_bottom"] = bottom
    return client
}

// Set the output page left margin.
//
// left - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *ImageToPdfClient) SetMarginLeft(left string) *ImageToPdfClient {
    client.fields["margin_left"] = left
    return client
}

// Set the output page margins.
//
// top - Set the output page top margin. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
// right - Set the output page right margin. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
// bottom - Set the output page bottom margin. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
// left - Set the output page left margin. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
func (client *ImageToPdfClient) SetPageMargins(top string, right string, bottom string, left string) *ImageToPdfClient {
    client.SetMarginTop(top)
    client.SetMarginRight(right)
    client.SetMarginBottom(bottom)
    client.SetMarginLeft(left)
    return client
}

// The page background color in RGB or RGBA hexadecimal format. The color fills the entire page regardless of the margins. If not page size is specified and the image format supports background (e.g. PDF, PNG), the background color is applied too.
//
// color - The value must be in RRGGBB or RRGGBBAA hexadecimal format.
func (client *ImageToPdfClient) SetPageBackgroundColor(color string) *ImageToPdfClient {
    client.fields["page_background_color"] = color
    return client
}

// Set the DPI resolution of the input image. The DPI affects margin options specified in points too (e.g. 1 point is equal to 1 pixel in 96 DPI).
//
// dpi - The DPI value.
func (client *ImageToPdfClient) SetDpi(dpi int) *ImageToPdfClient {
    client.fields["dpi"] = strconv.Itoa(dpi)
    return client
}

// Apply a watermark to each page of the output PDF file. A watermark can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the watermark.
//
// watermark - The file path to a local file. The file must exist and not be empty.
func (client *ImageToPdfClient) SetPageWatermark(watermark string) *ImageToPdfClient {
    client.files["page_watermark"] = watermark
    return client
}

// Load a file from the specified URL and apply the file as a watermark to each page of the output PDF. A watermark can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the watermark.
//
// url - Supported protocols are http:// and https://.
func (client *ImageToPdfClient) SetPageWatermarkUrl(url string) *ImageToPdfClient {
    client.fields["page_watermark_url"] = url
    return client
}

// Apply each page of a watermark to the corresponding page of the output PDF. A watermark can be either a PDF or an image.
//
// watermark - The file path to a local file. The file must exist and not be empty.
func (client *ImageToPdfClient) SetMultipageWatermark(watermark string) *ImageToPdfClient {
    client.files["multipage_watermark"] = watermark
    return client
}

// Load a file from the specified URL and apply each page of the file as a watermark to the corresponding page of the output PDF. A watermark can be either a PDF or an image.
//
// url - Supported protocols are http:// and https://.
func (client *ImageToPdfClient) SetMultipageWatermarkUrl(url string) *ImageToPdfClient {
    client.fields["multipage_watermark_url"] = url
    return client
}

// Apply a background to each page of the output PDF file. A background can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the background.
//
// background - The file path to a local file. The file must exist and not be empty.
func (client *ImageToPdfClient) SetPageBackground(background string) *ImageToPdfClient {
    client.files["page_background"] = background
    return client
}

// Load a file from the specified URL and apply the file as a background to each page of the output PDF. A background can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the background.
//
// url - Supported protocols are http:// and https://.
func (client *ImageToPdfClient) SetPageBackgroundUrl(url string) *ImageToPdfClient {
    client.fields["page_background_url"] = url
    return client
}

// Apply each page of a background to the corresponding page of the output PDF. A background can be either a PDF or an image.
//
// background - The file path to a local file. The file must exist and not be empty.
func (client *ImageToPdfClient) SetMultipageBackground(background string) *ImageToPdfClient {
    client.files["multipage_background"] = background
    return client
}

// Load a file from the specified URL and apply each page of the file as a background to the corresponding page of the output PDF. A background can be either a PDF or an image.
//
// url - Supported protocols are http:// and https://.
func (client *ImageToPdfClient) SetMultipageBackgroundUrl(url string) *ImageToPdfClient {
    client.fields["multipage_background_url"] = url
    return client
}

// Create linearized PDF. This is also known as Fast Web View.
//
// value - Set to true to create linearized PDF.
func (client *ImageToPdfClient) SetLinearize(value bool) *ImageToPdfClient {
    client.fields["linearize"] = strconv.FormatBool(value)
    return client
}

// Encrypt the PDF. This prevents search engines from indexing the contents.
//
// value - Set to true to enable PDF encryption.
func (client *ImageToPdfClient) SetEncrypt(value bool) *ImageToPdfClient {
    client.fields["encrypt"] = strconv.FormatBool(value)
    return client
}

// Protect the PDF with a user password. When a PDF has a user password, it must be supplied in order to view the document and to perform operations allowed by the access permissions.
//
// password - The user password.
func (client *ImageToPdfClient) SetUserPassword(password string) *ImageToPdfClient {
    client.fields["user_password"] = password
    return client
}

// Protect the PDF with an owner password. Supplying an owner password grants unlimited access to the PDF including changing the passwords and access permissions.
//
// password - The owner password.
func (client *ImageToPdfClient) SetOwnerPassword(password string) *ImageToPdfClient {
    client.fields["owner_password"] = password
    return client
}

// Disallow printing of the output PDF.
//
// value - Set to true to set the no-print flag in the output PDF.
func (client *ImageToPdfClient) SetNoPrint(value bool) *ImageToPdfClient {
    client.fields["no_print"] = strconv.FormatBool(value)
    return client
}

// Disallow modification of the output PDF.
//
// value - Set to true to set the read-only only flag in the output PDF.
func (client *ImageToPdfClient) SetNoModify(value bool) *ImageToPdfClient {
    client.fields["no_modify"] = strconv.FormatBool(value)
    return client
}

// Disallow text and graphics extraction from the output PDF.
//
// value - Set to true to set the no-copy flag in the output PDF.
func (client *ImageToPdfClient) SetNoCopy(value bool) *ImageToPdfClient {
    client.fields["no_copy"] = strconv.FormatBool(value)
    return client
}

// Set the title of the PDF.
//
// title - The title.
func (client *ImageToPdfClient) SetTitle(title string) *ImageToPdfClient {
    client.fields["title"] = title
    return client
}

// Set the subject of the PDF.
//
// subject - The subject.
func (client *ImageToPdfClient) SetSubject(subject string) *ImageToPdfClient {
    client.fields["subject"] = subject
    return client
}

// Set the author of the PDF.
//
// author - The author.
func (client *ImageToPdfClient) SetAuthor(author string) *ImageToPdfClient {
    client.fields["author"] = author
    return client
}

// Associate keywords with the document.
//
// keywords - The string with the keywords.
func (client *ImageToPdfClient) SetKeywords(keywords string) *ImageToPdfClient {
    client.fields["keywords"] = keywords
    return client
}

// Specify the page layout to be used when the document is opened.
//
// layout - Allowed values are single-page, one-column, two-column-left, two-column-right.
func (client *ImageToPdfClient) SetPageLayout(layout string) *ImageToPdfClient {
    client.fields["page_layout"] = layout
    return client
}

// Specify how the document should be displayed when opened.
//
// mode - Allowed values are full-screen, thumbnails, outlines.
func (client *ImageToPdfClient) SetPageMode(mode string) *ImageToPdfClient {
    client.fields["page_mode"] = mode
    return client
}

// Specify how the page should be displayed when opened.
//
// zoomType - Allowed values are fit-width, fit-height, fit-page.
func (client *ImageToPdfClient) SetInitialZoomType(zoomType string) *ImageToPdfClient {
    client.fields["initial_zoom_type"] = zoomType
    return client
}

// Display the specified page when the document is opened.
//
// page - Must be a positive integer.
func (client *ImageToPdfClient) SetInitialPage(page int) *ImageToPdfClient {
    client.fields["initial_page"] = strconv.Itoa(page)
    return client
}

// Specify the initial page zoom in percents when the document is opened.
//
// zoom - Must be a positive integer.
func (client *ImageToPdfClient) SetInitialZoom(zoom int) *ImageToPdfClient {
    client.fields["initial_zoom"] = strconv.Itoa(zoom)
    return client
}

// Specify whether to hide the viewer application's tool bars when the document is active.
//
// value - Set to true to hide tool bars.
func (client *ImageToPdfClient) SetHideToolbar(value bool) *ImageToPdfClient {
    client.fields["hide_toolbar"] = strconv.FormatBool(value)
    return client
}

// Specify whether to hide the viewer application's menu bar when the document is active.
//
// value - Set to true to hide the menu bar.
func (client *ImageToPdfClient) SetHideMenubar(value bool) *ImageToPdfClient {
    client.fields["hide_menubar"] = strconv.FormatBool(value)
    return client
}

// Specify whether to hide user interface elements in the document's window (such as scroll bars and navigation controls), leaving only the document's contents displayed.
//
// value - Set to true to hide ui elements.
func (client *ImageToPdfClient) SetHideWindowUi(value bool) *ImageToPdfClient {
    client.fields["hide_window_ui"] = strconv.FormatBool(value)
    return client
}

// Specify whether to resize the document's window to fit the size of the first displayed page.
//
// value - Set to true to resize the window.
func (client *ImageToPdfClient) SetFitWindow(value bool) *ImageToPdfClient {
    client.fields["fit_window"] = strconv.FormatBool(value)
    return client
}

// Specify whether to position the document's window in the center of the screen.
//
// value - Set to true to center the window.
func (client *ImageToPdfClient) SetCenterWindow(value bool) *ImageToPdfClient {
    client.fields["center_window"] = strconv.FormatBool(value)
    return client
}

// Specify whether the window's title bar should display the document title. If false , the title bar should instead display the name of the PDF file containing the document.
//
// value - Set to true to display the title.
func (client *ImageToPdfClient) SetDisplayTitle(value bool) *ImageToPdfClient {
    client.fields["display_title"] = strconv.FormatBool(value)
    return client
}

// Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the getDebugLogUrl method or available in conversion statistics.
//
// value - Set to true to enable the debug logging.
func (client *ImageToPdfClient) SetDebugLog(value bool) *ImageToPdfClient {
    client.fields["debug_log"] = strconv.FormatBool(value)
    return client
}

// Get the URL of the debug log for the last conversion.
func (client *ImageToPdfClient) GetDebugLogUrl() string {
    return client.helper.getDebugLogUrl()
}

// Get the number of conversion credits available in your account.
// This method can only be called after a call to one of the convertXtoY methods.
// The returned value can differ from the actual count if you run parallel conversions.
// The special value 999999 is returned if the information is not available.
func (client *ImageToPdfClient) GetRemainingCreditCount() int {
    return client.helper.getRemainingCreditCount()
}

// Get the number of credits consumed by the last conversion.
func (client *ImageToPdfClient) GetConsumedCreditCount() int {
    return client.helper.getConsumedCreditCount()
}

// Get the job id.
func (client *ImageToPdfClient) GetJobId() string {
    return client.helper.getJobId()
}

// Get the size of the output in bytes.
func (client *ImageToPdfClient) GetOutputSize() int {
    return client.helper.getOutputSize()
}

// Get the version details.
func (client *ImageToPdfClient) GetVersion() string {
    return fmt.Sprintf("client %s, API v2, converter %s", CLIENT_VERSION, client.helper.getConverterVersion())
}

// Tag the conversion with a custom value. The tag is used in conversion statistics. A value longer than 32 characters is cut off.
//
// tag - A string with the custom tag.
func (client *ImageToPdfClient) SetTag(tag string) *ImageToPdfClient {
    client.fields["tag"] = tag
    return client
}

// A proxy server used by the conversion process for accessing the source URLs with HTTP scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
//
// proxy - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
func (client *ImageToPdfClient) SetHttpProxy(proxy string) *ImageToPdfClient {
    client.fields["http_proxy"] = proxy
    return client
}

// A proxy server used by the conversion process for accessing the source URLs with HTTPS scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
//
// proxy - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
func (client *ImageToPdfClient) SetHttpsProxy(proxy string) *ImageToPdfClient {
    client.fields["https_proxy"] = proxy
    return client
}

// Set the converter version. Different versions may produce different output. Choose which one provides the best output for your case.
//
// version - The version identifier. Allowed values are 24.04, 20.10, 18.10, latest.
func (client *ImageToPdfClient) SetConverterVersion(version string) *ImageToPdfClient {
    client.helper.setConverterVersion(version)
    return client
}

// Specify whether to use HTTP or HTTPS when connecting to the PDFCrowd API.
// Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
//
// value - Set to true to use HTTP.
func (client *ImageToPdfClient) SetUseHttp(value bool) *ImageToPdfClient {
    client.helper.setUseHttp(value)
    return client
}

// Specifies the User-Agent HTTP header that the client library will use when interacting with the API.
//
// agent - The user agent string.
func (client *ImageToPdfClient) SetClientUserAgent(agent string) *ImageToPdfClient {
    client.helper.setUserAgent(agent)
    return client
}

// Set a custom user agent HTTP header. It can be useful if you are behind a proxy or a firewall.
//
// agent - The user agent string.
func (client *ImageToPdfClient) SetUserAgent(agent string) *ImageToPdfClient {
    client.helper.setUserAgent(agent)
    return client
}

// Specifies an HTTP proxy that the API client library will use to connect to the internet.
//
// host - The proxy hostname.
// port - The proxy port.
// userName - The username.
// password - The password.
func (client *ImageToPdfClient) SetProxy(host string, port int, userName string, password string) *ImageToPdfClient {
    client.helper.setProxy(host, port, userName, password)
    return client
}

// Specifies the number of automatic retries when the 502 or 503 HTTP status code is received. The status code indicates a temporary network issue. This feature can be disabled by setting to 0.
//
// count - Number of retries.
func (client *ImageToPdfClient) SetRetryCount(count int) *ImageToPdfClient {
    client.helper.setRetryCount(count)
    return client
}

// Conversion from PDF to HTML.
type PdfToHtmlClient struct {
    helper connectionHelper
    fields map[string]string
    files map[string]string
    rawData map[string][]byte
    fileId int
}

// Constructor for the PDFCrowd API client.
//
// userName - Your username at PDFCrowd.
// apiKey - Your API key.
func NewPdfToHtmlClient(userName string, apiKey string) PdfToHtmlClient {
    helper := newConnectionHelper(userName, apiKey)
    fields := map[string]string{
        "input_format": "pdf",
        "output_format": "html",
    }
    return PdfToHtmlClient{ helper, fields, make(map[string]string), make(map[string][]byte), 1}
}

// Convert a PDF.
//
// url - The address of the PDF to convert. Supported protocols are http:// and https://.
func (client *PdfToHtmlClient) ConvertUrl(url string) ([]byte, error) {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return nil, NewError(createInvalidValueMessage(url, "ConvertUrl", "pdf-to-html", "Supported protocols are http:// and https://.", "convert_url"), 470)
    }
    
    client.fields["url"] = url
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert a PDF and write the result to an output stream.
//
// url - The address of the PDF to convert. Supported protocols are http:// and https://.
// outStream - The output stream that will contain the conversion output.
func (client *PdfToHtmlClient) ConvertUrlToStream(url string, outStream io.Writer) error {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return NewError(createInvalidValueMessage(url, "ConvertUrlToStream::url", "pdf-to-html", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470)
    }
    
    client.fields["url"] = url
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert a PDF and write the result to a local file.
//
// url - The address of the PDF to convert. Supported protocols are http:// and https://.
// filePath - The output file path. The string must not be empty. The converter generates an HTML or ZIP file. If ZIP file is generated, the file path must have a ZIP or zip extension.
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

// Convert a local file.
//
// file - The path to a local file to convert. The file must exist and not be empty.
func (client *PdfToHtmlClient) ConvertFile(file string) ([]byte, error) {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return nil, NewError(createInvalidValueMessage(file, "ConvertFile", "pdf-to-html", "The file must exist and not be empty.", "convert_file"), 470)
    }
    
    client.files["file"] = file
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert a local file and write the result to an output stream.
//
// file - The path to a local file to convert. The file must exist and not be empty.
// outStream - The output stream that will contain the conversion output.
func (client *PdfToHtmlClient) ConvertFileToStream(file string, outStream io.Writer) error {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return NewError(createInvalidValueMessage(file, "ConvertFileToStream::file", "pdf-to-html", "The file must exist and not be empty.", "convert_file_to_stream"), 470)
    }
    
    client.files["file"] = file
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert a local file and write the result to a local file.
//
// file - The path to a local file to convert. The file must exist and not be empty.
// filePath - The output file path. The string must not be empty. The converter generates an HTML or ZIP file. If ZIP file is generated, the file path must have a ZIP or zip extension.
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

// Convert raw data.
//
// data - The raw content to be converted.
func (client *PdfToHtmlClient) ConvertRawData(data []byte) ([]byte, error) {
    client.rawData["file"] = data
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert raw data and write the result to an output stream.
//
// data - The raw content to be converted.
// outStream - The output stream that will contain the conversion output.
func (client *PdfToHtmlClient) ConvertRawDataToStream(data []byte, outStream io.Writer) error {
    client.rawData["file"] = data
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert raw data to a file.
//
// data - The raw content to be converted.
// filePath - The output file path. The string must not be empty. The converter generates an HTML or ZIP file. If ZIP file is generated, the file path must have a ZIP or zip extension.
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

// Convert the contents of an input stream.
//
// inStream - The input stream with source data.
func (client *PdfToHtmlClient) ConvertStream(inStream io.Reader) ([]byte, error) {
    data, errRead := ioutil.ReadAll(inStream)
    if errRead != nil {
        return nil, errRead
    }

    client.rawData["stream"] = data
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert the contents of an input stream and write the result to an output stream.
//
// inStream - The input stream with source data.
// outStream - The output stream that will contain the conversion output.
func (client *PdfToHtmlClient) ConvertStreamToStream(inStream io.Reader, outStream io.Writer) error {
    data, errRead := ioutil.ReadAll(inStream)
    if errRead != nil {
        return errRead
    }

    client.rawData["stream"] = data
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert the contents of an input stream and write the result to a local file.
//
// inStream - The input stream with source data.
// filePath - The output file path. The string must not be empty. The converter generates an HTML or ZIP file. If ZIP file is generated, the file path must have a ZIP or zip extension.
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

// Password to open the encrypted PDF file.
//
// password - The input PDF password.
func (client *PdfToHtmlClient) SetPdfPassword(password string) *PdfToHtmlClient {
    client.fields["pdf_password"] = password
    return client
}

// Set the scaling factor (zoom) for the main page area.
//
// factor - The percentage value. Must be a positive integer.
func (client *PdfToHtmlClient) SetScaleFactor(factor int) *PdfToHtmlClient {
    client.fields["scale_factor"] = strconv.Itoa(factor)
    return client
}

// Set the page range to print.
//
// pages - A comma separated list of page numbers or ranges.
func (client *PdfToHtmlClient) SetPrintPageRange(pages string) *PdfToHtmlClient {
    client.fields["print_page_range"] = pages
    return client
}

// Set the output graphics DPI.
//
// dpi - The DPI value.
func (client *PdfToHtmlClient) SetDpi(dpi int) *PdfToHtmlClient {
    client.fields["dpi"] = strconv.Itoa(dpi)
    return client
}

// Specifies where the images are stored.
//
// mode - The image storage mode. Allowed values are embed, separate, none.
func (client *PdfToHtmlClient) SetImageMode(mode string) *PdfToHtmlClient {
    client.fields["image_mode"] = mode
    return client
}

// Specifies the format for the output images.
//
// imageFormat - The image format. Allowed values are png, jpg, svg.
func (client *PdfToHtmlClient) SetImageFormat(imageFormat string) *PdfToHtmlClient {
    client.fields["image_format"] = imageFormat
    return client
}

// Specifies where the style sheets are stored.
//
// mode - The style sheet storage mode. Allowed values are embed, separate.
func (client *PdfToHtmlClient) SetCssMode(mode string) *PdfToHtmlClient {
    client.fields["css_mode"] = mode
    return client
}

// Specifies where the fonts are stored.
//
// mode - The font storage mode. Allowed values are embed, separate.
func (client *PdfToHtmlClient) SetFontMode(mode string) *PdfToHtmlClient {
    client.fields["font_mode"] = mode
    return client
}

// Sets the processing mode for handling Type 3 fonts.
//
// mode - The type3 font mode. Allowed values are raster, convert.
func (client *PdfToHtmlClient) SetType3Mode(mode string) *PdfToHtmlClient {
    client.fields["type3_mode"] = mode
    return client
}

// Converts ligatures, two or more letters combined into a single glyph, back into their individual ASCII characters.
//
// value - Set to true to split ligatures.
func (client *PdfToHtmlClient) SetSplitLigatures(value bool) *PdfToHtmlClient {
    client.fields["split_ligatures"] = strconv.FormatBool(value)
    return client
}

// Apply custom CSS to the output HTML document. It allows you to modify the visual appearance and layout. Tip: Using !important in custom CSS provides a way to prioritize and override conflicting styles.
//
// css - A string containing valid CSS. The string must not be empty.
func (client *PdfToHtmlClient) SetCustomCss(css string) *PdfToHtmlClient {
    client.fields["custom_css"] = css
    return client
}

// Add the specified prefix to all id and class attributes in the HTML content, creating a namespace for safe integration into another HTML document. This ensures unique identifiers, preventing conflicts when merging with other HTML.
//
// prefix - The prefix to add before each id and class attribute name. Start with a letter or underscore, and use only letters, numbers, hyphens, underscores, or colons.
func (client *PdfToHtmlClient) SetHtmlNamespace(prefix string) *PdfToHtmlClient {
    client.fields["html_namespace"] = prefix
    return client
}

// A helper method to determine if the output file is a zip archive. The output of the conversion may be either an HTML file or a zip file containing the HTML and its external assets.
func (client *PdfToHtmlClient) IsZippedOutput() bool {
    return client.fields["image_mode"] == "separate" || client.fields["css_mode"] == "separate" || client.fields["font_mode"] == "separate" || client.fields["force_zip"] == "true"
}

// Enforces the zip output format.
//
// value - Set to true to get the output as a zip archive.
func (client *PdfToHtmlClient) SetForceZip(value bool) *PdfToHtmlClient {
    client.fields["force_zip"] = strconv.FormatBool(value)
    return client
}

// Set the HTML title. The title from the input PDF is used by default.
//
// title - The HTML title.
func (client *PdfToHtmlClient) SetTitle(title string) *PdfToHtmlClient {
    client.fields["title"] = title
    return client
}

// Set the HTML subject. The subject from the input PDF is used by default.
//
// subject - The HTML subject.
func (client *PdfToHtmlClient) SetSubject(subject string) *PdfToHtmlClient {
    client.fields["subject"] = subject
    return client
}

// Set the HTML author. The author from the input PDF is used by default.
//
// author - The HTML author.
func (client *PdfToHtmlClient) SetAuthor(author string) *PdfToHtmlClient {
    client.fields["author"] = author
    return client
}

// Associate keywords with the HTML document. Keywords from the input PDF are used by default.
//
// keywords - The string containing the keywords.
func (client *PdfToHtmlClient) SetKeywords(keywords string) *PdfToHtmlClient {
    client.fields["keywords"] = keywords
    return client
}

// Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the getDebugLogUrl method or available in conversion statistics.
//
// value - Set to true to enable the debug logging.
func (client *PdfToHtmlClient) SetDebugLog(value bool) *PdfToHtmlClient {
    client.fields["debug_log"] = strconv.FormatBool(value)
    return client
}

// Get the URL of the debug log for the last conversion.
func (client *PdfToHtmlClient) GetDebugLogUrl() string {
    return client.helper.getDebugLogUrl()
}

// Get the number of conversion credits available in your account.
// This method can only be called after a call to one of the convertXtoY methods.
// The returned value can differ from the actual count if you run parallel conversions.
// The special value 999999 is returned if the information is not available.
func (client *PdfToHtmlClient) GetRemainingCreditCount() int {
    return client.helper.getRemainingCreditCount()
}

// Get the number of credits consumed by the last conversion.
func (client *PdfToHtmlClient) GetConsumedCreditCount() int {
    return client.helper.getConsumedCreditCount()
}

// Get the job id.
func (client *PdfToHtmlClient) GetJobId() string {
    return client.helper.getJobId()
}

// Get the number of pages in the output document.
func (client *PdfToHtmlClient) GetPageCount() int {
    return client.helper.getPageCount()
}

// Get the size of the output in bytes.
func (client *PdfToHtmlClient) GetOutputSize() int {
    return client.helper.getOutputSize()
}

// Get the version details.
func (client *PdfToHtmlClient) GetVersion() string {
    return fmt.Sprintf("client %s, API v2, converter %s", CLIENT_VERSION, client.helper.getConverterVersion())
}

// Tag the conversion with a custom value. The tag is used in conversion statistics. A value longer than 32 characters is cut off.
//
// tag - A string with the custom tag.
func (client *PdfToHtmlClient) SetTag(tag string) *PdfToHtmlClient {
    client.fields["tag"] = tag
    return client
}

// A proxy server used by the conversion process for accessing the source URLs with HTTP scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
//
// proxy - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
func (client *PdfToHtmlClient) SetHttpProxy(proxy string) *PdfToHtmlClient {
    client.fields["http_proxy"] = proxy
    return client
}

// A proxy server used by the conversion process for accessing the source URLs with HTTPS scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
//
// proxy - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
func (client *PdfToHtmlClient) SetHttpsProxy(proxy string) *PdfToHtmlClient {
    client.fields["https_proxy"] = proxy
    return client
}

// Set the converter version. Different versions may produce different output. Choose which one provides the best output for your case.
//
// version - The version identifier. Allowed values are 24.04, 20.10, 18.10, latest.
func (client *PdfToHtmlClient) SetConverterVersion(version string) *PdfToHtmlClient {
    client.helper.setConverterVersion(version)
    return client
}

// Specify whether to use HTTP or HTTPS when connecting to the PDFCrowd API.
// Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
//
// value - Set to true to use HTTP.
func (client *PdfToHtmlClient) SetUseHttp(value bool) *PdfToHtmlClient {
    client.helper.setUseHttp(value)
    return client
}

// Specifies the User-Agent HTTP header that the client library will use when interacting with the API.
//
// agent - The user agent string.
func (client *PdfToHtmlClient) SetClientUserAgent(agent string) *PdfToHtmlClient {
    client.helper.setUserAgent(agent)
    return client
}

// Set a custom user agent HTTP header. It can be useful if you are behind a proxy or a firewall.
//
// agent - The user agent string.
func (client *PdfToHtmlClient) SetUserAgent(agent string) *PdfToHtmlClient {
    client.helper.setUserAgent(agent)
    return client
}

// Specifies an HTTP proxy that the API client library will use to connect to the internet.
//
// host - The proxy hostname.
// port - The proxy port.
// userName - The username.
// password - The password.
func (client *PdfToHtmlClient) SetProxy(host string, port int, userName string, password string) *PdfToHtmlClient {
    client.helper.setProxy(host, port, userName, password)
    return client
}

// Specifies the number of automatic retries when the 502 or 503 HTTP status code is received. The status code indicates a temporary network issue. This feature can be disabled by setting to 0.
//
// count - Number of retries.
func (client *PdfToHtmlClient) SetRetryCount(count int) *PdfToHtmlClient {
    client.helper.setRetryCount(count)
    return client
}

func (client *PdfToHtmlClient) isOutputTypeValid(file_path string) bool {
    extension := filepath.Ext(file_path)
    return (extension == ".zip") == client.IsZippedOutput()
}
// Conversion from PDF to text.
type PdfToTextClient struct {
    helper connectionHelper
    fields map[string]string
    files map[string]string
    rawData map[string][]byte
    fileId int
}

// Constructor for the PDFCrowd API client.
//
// userName - Your username at PDFCrowd.
// apiKey - Your API key.
func NewPdfToTextClient(userName string, apiKey string) PdfToTextClient {
    helper := newConnectionHelper(userName, apiKey)
    fields := map[string]string{
        "input_format": "pdf",
        "output_format": "txt",
    }
    return PdfToTextClient{ helper, fields, make(map[string]string), make(map[string][]byte), 1}
}

// Convert a PDF.
//
// url - The address of the PDF to convert. Supported protocols are http:// and https://.
func (client *PdfToTextClient) ConvertUrl(url string) ([]byte, error) {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return nil, NewError(createInvalidValueMessage(url, "ConvertUrl", "pdf-to-text", "Supported protocols are http:// and https://.", "convert_url"), 470)
    }
    
    client.fields["url"] = url
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert a PDF and write the result to an output stream.
//
// url - The address of the PDF to convert. Supported protocols are http:// and https://.
// outStream - The output stream that will contain the conversion output.
func (client *PdfToTextClient) ConvertUrlToStream(url string, outStream io.Writer) error {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return NewError(createInvalidValueMessage(url, "ConvertUrlToStream::url", "pdf-to-text", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470)
    }
    
    client.fields["url"] = url
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert a PDF and write the result to a local file.
//
// url - The address of the PDF to convert. Supported protocols are http:// and https://.
// filePath - The output file path. The string must not be empty.
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

// Convert a local file.
//
// file - The path to a local file to convert. The file must exist and not be empty.
func (client *PdfToTextClient) ConvertFile(file string) ([]byte, error) {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return nil, NewError(createInvalidValueMessage(file, "ConvertFile", "pdf-to-text", "The file must exist and not be empty.", "convert_file"), 470)
    }
    
    client.files["file"] = file
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert a local file and write the result to an output stream.
//
// file - The path to a local file to convert. The file must exist and not be empty.
// outStream - The output stream that will contain the conversion output.
func (client *PdfToTextClient) ConvertFileToStream(file string, outStream io.Writer) error {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return NewError(createInvalidValueMessage(file, "ConvertFileToStream::file", "pdf-to-text", "The file must exist and not be empty.", "convert_file_to_stream"), 470)
    }
    
    client.files["file"] = file
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert a local file and write the result to a local file.
//
// file - The path to a local file to convert. The file must exist and not be empty.
// filePath - The output file path. The string must not be empty.
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

// Convert raw data.
//
// data - The raw content to be converted.
func (client *PdfToTextClient) ConvertRawData(data []byte) ([]byte, error) {
    client.rawData["file"] = data
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert raw data and write the result to an output stream.
//
// data - The raw content to be converted.
// outStream - The output stream that will contain the conversion output.
func (client *PdfToTextClient) ConvertRawDataToStream(data []byte, outStream io.Writer) error {
    client.rawData["file"] = data
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert raw data to a file.
//
// data - The raw content to be converted.
// filePath - The output file path. The string must not be empty.
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

// Convert the contents of an input stream.
//
// inStream - The input stream with source data.
func (client *PdfToTextClient) ConvertStream(inStream io.Reader) ([]byte, error) {
    data, errRead := ioutil.ReadAll(inStream)
    if errRead != nil {
        return nil, errRead
    }

    client.rawData["stream"] = data
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert the contents of an input stream and write the result to an output stream.
//
// inStream - The input stream with source data.
// outStream - The output stream that will contain the conversion output.
func (client *PdfToTextClient) ConvertStreamToStream(inStream io.Reader, outStream io.Writer) error {
    data, errRead := ioutil.ReadAll(inStream)
    if errRead != nil {
        return errRead
    }

    client.rawData["stream"] = data
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert the contents of an input stream and write the result to a local file.
//
// inStream - The input stream with source data.
// filePath - The output file path. The string must not be empty.
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

// The password to open the encrypted PDF file.
//
// password - The input PDF password.
func (client *PdfToTextClient) SetPdfPassword(password string) *PdfToTextClient {
    client.fields["pdf_password"] = password
    return client
}

// Set the page range to print.
//
// pages - A comma separated list of page numbers or ranges.
func (client *PdfToTextClient) SetPrintPageRange(pages string) *PdfToTextClient {
    client.fields["print_page_range"] = pages
    return client
}

// Ignore the original PDF layout.
//
// value - Set to true to ignore the layout.
func (client *PdfToTextClient) SetNoLayout(value bool) *PdfToTextClient {
    client.fields["no_layout"] = strconv.FormatBool(value)
    return client
}

// The end-of-line convention for the text output.
//
// eol - Allowed values are unix, dos, mac.
func (client *PdfToTextClient) SetEol(eol string) *PdfToTextClient {
    client.fields["eol"] = eol
    return client
}

// Specify the page break mode for the text output.
//
// mode - Allowed values are none, default, custom.
func (client *PdfToTextClient) SetPageBreakMode(mode string) *PdfToTextClient {
    client.fields["page_break_mode"] = mode
    return client
}

// Specify the custom page break.
//
// pageBreak - String to insert between the pages.
func (client *PdfToTextClient) SetCustomPageBreak(pageBreak string) *PdfToTextClient {
    client.fields["custom_page_break"] = pageBreak
    return client
}

// Specify the paragraph detection mode.
//
// mode - Allowed values are none, bounding-box, characters.
func (client *PdfToTextClient) SetParagraphMode(mode string) *PdfToTextClient {
    client.fields["paragraph_mode"] = mode
    return client
}

// Set the maximum line spacing when the paragraph detection mode is enabled.
//
// threshold - The value must be a positive integer percentage.
func (client *PdfToTextClient) SetLineSpacingThreshold(threshold string) *PdfToTextClient {
    client.fields["line_spacing_threshold"] = threshold
    return client
}

// Remove the hyphen character from the end of lines.
//
// value - Set to true to remove hyphens.
func (client *PdfToTextClient) SetRemoveHyphenation(value bool) *PdfToTextClient {
    client.fields["remove_hyphenation"] = strconv.FormatBool(value)
    return client
}

// Remove empty lines from the text output.
//
// value - Set to true to remove empty lines.
func (client *PdfToTextClient) SetRemoveEmptyLines(value bool) *PdfToTextClient {
    client.fields["remove_empty_lines"] = strconv.FormatBool(value)
    return client
}

// Set the top left X coordinate of the crop area in points.
//
// x - Must be a positive integer or 0.
func (client *PdfToTextClient) SetCropAreaX(x int) *PdfToTextClient {
    client.fields["crop_area_x"] = strconv.Itoa(x)
    return client
}

// Set the top left Y coordinate of the crop area in points.
//
// y - Must be a positive integer or 0.
func (client *PdfToTextClient) SetCropAreaY(y int) *PdfToTextClient {
    client.fields["crop_area_y"] = strconv.Itoa(y)
    return client
}

// Set the width of the crop area in points.
//
// width - Must be a positive integer or 0.
func (client *PdfToTextClient) SetCropAreaWidth(width int) *PdfToTextClient {
    client.fields["crop_area_width"] = strconv.Itoa(width)
    return client
}

// Set the height of the crop area in points.
//
// height - Must be a positive integer or 0.
func (client *PdfToTextClient) SetCropAreaHeight(height int) *PdfToTextClient {
    client.fields["crop_area_height"] = strconv.Itoa(height)
    return client
}

// Set the crop area. It allows to extract just a part of a PDF page.
//
// x - Set the top left X coordinate of the crop area in points. Must be a positive integer or 0.
// y - Set the top left Y coordinate of the crop area in points. Must be a positive integer or 0.
// width - Set the width of the crop area in points. Must be a positive integer or 0.
// height - Set the height of the crop area in points. Must be a positive integer or 0.
func (client *PdfToTextClient) SetCropArea(x int, y int, width int, height int) *PdfToTextClient {
    client.SetCropAreaX(x)
    client.SetCropAreaY(y)
    client.SetCropAreaWidth(width)
    client.SetCropAreaHeight(height)
    return client
}

// Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the getDebugLogUrl method or available in conversion statistics.
//
// value - Set to true to enable the debug logging.
func (client *PdfToTextClient) SetDebugLog(value bool) *PdfToTextClient {
    client.fields["debug_log"] = strconv.FormatBool(value)
    return client
}

// Get the URL of the debug log for the last conversion.
func (client *PdfToTextClient) GetDebugLogUrl() string {
    return client.helper.getDebugLogUrl()
}

// Get the number of conversion credits available in your account.
// This method can only be called after a call to one of the convertXtoY methods.
// The returned value can differ from the actual count if you run parallel conversions.
// The special value 999999 is returned if the information is not available.
func (client *PdfToTextClient) GetRemainingCreditCount() int {
    return client.helper.getRemainingCreditCount()
}

// Get the number of credits consumed by the last conversion.
func (client *PdfToTextClient) GetConsumedCreditCount() int {
    return client.helper.getConsumedCreditCount()
}

// Get the job id.
func (client *PdfToTextClient) GetJobId() string {
    return client.helper.getJobId()
}

// Get the number of pages in the output document.
func (client *PdfToTextClient) GetPageCount() int {
    return client.helper.getPageCount()
}

// Get the size of the output in bytes.
func (client *PdfToTextClient) GetOutputSize() int {
    return client.helper.getOutputSize()
}

// Get the version details.
func (client *PdfToTextClient) GetVersion() string {
    return fmt.Sprintf("client %s, API v2, converter %s", CLIENT_VERSION, client.helper.getConverterVersion())
}

// Tag the conversion with a custom value. The tag is used in conversion statistics. A value longer than 32 characters is cut off.
//
// tag - A string with the custom tag.
func (client *PdfToTextClient) SetTag(tag string) *PdfToTextClient {
    client.fields["tag"] = tag
    return client
}

// A proxy server used by the conversion process for accessing the source URLs with HTTP scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
//
// proxy - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
func (client *PdfToTextClient) SetHttpProxy(proxy string) *PdfToTextClient {
    client.fields["http_proxy"] = proxy
    return client
}

// A proxy server used by the conversion process for accessing the source URLs with HTTPS scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
//
// proxy - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
func (client *PdfToTextClient) SetHttpsProxy(proxy string) *PdfToTextClient {
    client.fields["https_proxy"] = proxy
    return client
}

// Specify whether to use HTTP or HTTPS when connecting to the PDFCrowd API.
// Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
//
// value - Set to true to use HTTP.
func (client *PdfToTextClient) SetUseHttp(value bool) *PdfToTextClient {
    client.helper.setUseHttp(value)
    return client
}

// Specifies the User-Agent HTTP header that the client library will use when interacting with the API.
//
// agent - The user agent string.
func (client *PdfToTextClient) SetClientUserAgent(agent string) *PdfToTextClient {
    client.helper.setUserAgent(agent)
    return client
}

// Set a custom user agent HTTP header. It can be useful if you are behind a proxy or a firewall.
//
// agent - The user agent string.
func (client *PdfToTextClient) SetUserAgent(agent string) *PdfToTextClient {
    client.helper.setUserAgent(agent)
    return client
}

// Specifies an HTTP proxy that the API client library will use to connect to the internet.
//
// host - The proxy hostname.
// port - The proxy port.
// userName - The username.
// password - The password.
func (client *PdfToTextClient) SetProxy(host string, port int, userName string, password string) *PdfToTextClient {
    client.helper.setProxy(host, port, userName, password)
    return client
}

// Specifies the number of automatic retries when the 502 or 503 HTTP status code is received. The status code indicates a temporary network issue. This feature can be disabled by setting to 0.
//
// count - Number of retries.
func (client *PdfToTextClient) SetRetryCount(count int) *PdfToTextClient {
    client.helper.setRetryCount(count)
    return client
}

// Conversion from PDF to image.
type PdfToImageClient struct {
    helper connectionHelper
    fields map[string]string
    files map[string]string
    rawData map[string][]byte
    fileId int
}

// Constructor for the PDFCrowd API client.
//
// userName - Your username at PDFCrowd.
// apiKey - Your API key.
func NewPdfToImageClient(userName string, apiKey string) PdfToImageClient {
    helper := newConnectionHelper(userName, apiKey)
    fields := map[string]string{
        "input_format": "pdf",
        "output_format": "png",
    }
    return PdfToImageClient{ helper, fields, make(map[string]string), make(map[string][]byte), 1}
}

// Convert an image.
//
// url - The address of the image to convert. Supported protocols are http:// and https://.
func (client *PdfToImageClient) ConvertUrl(url string) ([]byte, error) {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return nil, NewError(createInvalidValueMessage(url, "ConvertUrl", "pdf-to-image", "Supported protocols are http:// and https://.", "convert_url"), 470)
    }
    
    client.fields["url"] = url
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert an image and write the result to an output stream.
//
// url - The address of the image to convert. Supported protocols are http:// and https://.
// outStream - The output stream that will contain the conversion output.
func (client *PdfToImageClient) ConvertUrlToStream(url string, outStream io.Writer) error {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return NewError(createInvalidValueMessage(url, "ConvertUrlToStream::url", "pdf-to-image", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470)
    }
    
    client.fields["url"] = url
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert an image and write the result to a local file.
//
// url - The address of the image to convert. Supported protocols are http:// and https://.
// filePath - The output file path. The string must not be empty.
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

// Convert a local file.
//
// file - The path to a local file to convert. The file must exist and not be empty.
func (client *PdfToImageClient) ConvertFile(file string) ([]byte, error) {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return nil, NewError(createInvalidValueMessage(file, "ConvertFile", "pdf-to-image", "The file must exist and not be empty.", "convert_file"), 470)
    }
    
    client.files["file"] = file
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert a local file and write the result to an output stream.
//
// file - The path to a local file to convert. The file must exist and not be empty.
// outStream - The output stream that will contain the conversion output.
func (client *PdfToImageClient) ConvertFileToStream(file string, outStream io.Writer) error {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return NewError(createInvalidValueMessage(file, "ConvertFileToStream::file", "pdf-to-image", "The file must exist and not be empty.", "convert_file_to_stream"), 470)
    }
    
    client.files["file"] = file
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert a local file and write the result to a local file.
//
// file - The path to a local file to convert. The file must exist and not be empty.
// filePath - The output file path. The string must not be empty.
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

// Convert raw data.
//
// data - The raw content to be converted.
func (client *PdfToImageClient) ConvertRawData(data []byte) ([]byte, error) {
    client.rawData["file"] = data
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert raw data and write the result to an output stream.
//
// data - The raw content to be converted.
// outStream - The output stream that will contain the conversion output.
func (client *PdfToImageClient) ConvertRawDataToStream(data []byte, outStream io.Writer) error {
    client.rawData["file"] = data
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert raw data to a file.
//
// data - The raw content to be converted.
// filePath - The output file path. The string must not be empty.
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

// Convert the contents of an input stream.
//
// inStream - The input stream with source data.
func (client *PdfToImageClient) ConvertStream(inStream io.Reader) ([]byte, error) {
    data, errRead := ioutil.ReadAll(inStream)
    if errRead != nil {
        return nil, errRead
    }

    client.rawData["stream"] = data
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert the contents of an input stream and write the result to an output stream.
//
// inStream - The input stream with source data.
// outStream - The output stream that will contain the conversion output.
func (client *PdfToImageClient) ConvertStreamToStream(inStream io.Reader, outStream io.Writer) error {
    data, errRead := ioutil.ReadAll(inStream)
    if errRead != nil {
        return errRead
    }

    client.rawData["stream"] = data
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert the contents of an input stream and write the result to a local file.
//
// inStream - The input stream with source data.
// filePath - The output file path. The string must not be empty.
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

// The format of the output file.
//
// outputFormat - Allowed values are png, jpg, gif, tiff, bmp, ico, ppm, pgm, pbm, pnm, psb, pct, ras, tga, sgi, sun, webp.
func (client *PdfToImageClient) SetOutputFormat(outputFormat string) *PdfToImageClient {
    client.fields["output_format"] = outputFormat
    return client
}

// Password to open the encrypted PDF file.
//
// password - The input PDF password.
func (client *PdfToImageClient) SetPdfPassword(password string) *PdfToImageClient {
    client.fields["pdf_password"] = password
    return client
}

// Set the page range to print.
//
// pages - A comma separated list of page numbers or ranges.
func (client *PdfToImageClient) SetPrintPageRange(pages string) *PdfToImageClient {
    client.fields["print_page_range"] = pages
    return client
}

// Set the output graphics DPI.
//
// dpi - The DPI value.
func (client *PdfToImageClient) SetDpi(dpi int) *PdfToImageClient {
    client.fields["dpi"] = strconv.Itoa(dpi)
    return client
}

// A helper method to determine if the output file from a conversion process is a zip archive. The conversion output can be either a single image file or a zip file containing one or more image files. This method should be called after the conversion has been successfully completed.
func (client *PdfToImageClient) IsZippedOutput() bool {
    return client.fields["force_zip"] == "true" || client.GetPageCount() > 1
}

// Enforces the zip output format.
//
// value - Set to true to get the output as a zip archive.
func (client *PdfToImageClient) SetForceZip(value bool) *PdfToImageClient {
    client.fields["force_zip"] = strconv.FormatBool(value)
    return client
}

// Use the crop box rather than media box.
//
// value - Set to true to use crop box.
func (client *PdfToImageClient) SetUseCropbox(value bool) *PdfToImageClient {
    client.fields["use_cropbox"] = strconv.FormatBool(value)
    return client
}

// Set the top left X coordinate of the crop area in points.
//
// x - Must be a positive integer or 0.
func (client *PdfToImageClient) SetCropAreaX(x int) *PdfToImageClient {
    client.fields["crop_area_x"] = strconv.Itoa(x)
    return client
}

// Set the top left Y coordinate of the crop area in points.
//
// y - Must be a positive integer or 0.
func (client *PdfToImageClient) SetCropAreaY(y int) *PdfToImageClient {
    client.fields["crop_area_y"] = strconv.Itoa(y)
    return client
}

// Set the width of the crop area in points.
//
// width - Must be a positive integer or 0.
func (client *PdfToImageClient) SetCropAreaWidth(width int) *PdfToImageClient {
    client.fields["crop_area_width"] = strconv.Itoa(width)
    return client
}

// Set the height of the crop area in points.
//
// height - Must be a positive integer or 0.
func (client *PdfToImageClient) SetCropAreaHeight(height int) *PdfToImageClient {
    client.fields["crop_area_height"] = strconv.Itoa(height)
    return client
}

// Set the crop area. It allows to extract just a part of a PDF page.
//
// x - Set the top left X coordinate of the crop area in points. Must be a positive integer or 0.
// y - Set the top left Y coordinate of the crop area in points. Must be a positive integer or 0.
// width - Set the width of the crop area in points. Must be a positive integer or 0.
// height - Set the height of the crop area in points. Must be a positive integer or 0.
func (client *PdfToImageClient) SetCropArea(x int, y int, width int, height int) *PdfToImageClient {
    client.SetCropAreaX(x)
    client.SetCropAreaY(y)
    client.SetCropAreaWidth(width)
    client.SetCropAreaHeight(height)
    return client
}

// Generate a grayscale image.
//
// value - Set to true to generate a grayscale image.
func (client *PdfToImageClient) SetUseGrayscale(value bool) *PdfToImageClient {
    client.fields["use_grayscale"] = strconv.FormatBool(value)
    return client
}

// Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the getDebugLogUrl method or available in conversion statistics.
//
// value - Set to true to enable the debug logging.
func (client *PdfToImageClient) SetDebugLog(value bool) *PdfToImageClient {
    client.fields["debug_log"] = strconv.FormatBool(value)
    return client
}

// Get the URL of the debug log for the last conversion.
func (client *PdfToImageClient) GetDebugLogUrl() string {
    return client.helper.getDebugLogUrl()
}

// Get the number of conversion credits available in your account.
// This method can only be called after a call to one of the convertXtoY methods.
// The returned value can differ from the actual count if you run parallel conversions.
// The special value 999999 is returned if the information is not available.
func (client *PdfToImageClient) GetRemainingCreditCount() int {
    return client.helper.getRemainingCreditCount()
}

// Get the number of credits consumed by the last conversion.
func (client *PdfToImageClient) GetConsumedCreditCount() int {
    return client.helper.getConsumedCreditCount()
}

// Get the job id.
func (client *PdfToImageClient) GetJobId() string {
    return client.helper.getJobId()
}

// Get the number of pages in the output document.
func (client *PdfToImageClient) GetPageCount() int {
    return client.helper.getPageCount()
}

// Get the size of the output in bytes.
func (client *PdfToImageClient) GetOutputSize() int {
    return client.helper.getOutputSize()
}

// Get the version details.
func (client *PdfToImageClient) GetVersion() string {
    return fmt.Sprintf("client %s, API v2, converter %s", CLIENT_VERSION, client.helper.getConverterVersion())
}

// Tag the conversion with a custom value. The tag is used in conversion statistics. A value longer than 32 characters is cut off.
//
// tag - A string with the custom tag.
func (client *PdfToImageClient) SetTag(tag string) *PdfToImageClient {
    client.fields["tag"] = tag
    return client
}

// A proxy server used by the conversion process for accessing the source URLs with HTTP scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
//
// proxy - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
func (client *PdfToImageClient) SetHttpProxy(proxy string) *PdfToImageClient {
    client.fields["http_proxy"] = proxy
    return client
}

// A proxy server used by the conversion process for accessing the source URLs with HTTPS scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
//
// proxy - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
func (client *PdfToImageClient) SetHttpsProxy(proxy string) *PdfToImageClient {
    client.fields["https_proxy"] = proxy
    return client
}

// Specify whether to use HTTP or HTTPS when connecting to the PDFCrowd API.
// Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
//
// value - Set to true to use HTTP.
func (client *PdfToImageClient) SetUseHttp(value bool) *PdfToImageClient {
    client.helper.setUseHttp(value)
    return client
}

// Specifies the User-Agent HTTP header that the client library will use when interacting with the API.
//
// agent - The user agent string.
func (client *PdfToImageClient) SetClientUserAgent(agent string) *PdfToImageClient {
    client.helper.setUserAgent(agent)
    return client
}

// Set a custom user agent HTTP header. It can be useful if you are behind a proxy or a firewall.
//
// agent - The user agent string.
func (client *PdfToImageClient) SetUserAgent(agent string) *PdfToImageClient {
    client.helper.setUserAgent(agent)
    return client
}

// Specifies an HTTP proxy that the API client library will use to connect to the internet.
//
// host - The proxy hostname.
// port - The proxy port.
// userName - The username.
// password - The password.
func (client *PdfToImageClient) SetProxy(host string, port int, userName string, password string) *PdfToImageClient {
    client.helper.setProxy(host, port, userName, password)
    return client
}

// Specifies the number of automatic retries when the 502 or 503 HTTP status code is received. The status code indicates a temporary network issue. This feature can be disabled by setting to 0.
//
// count - Number of retries.
func (client *PdfToImageClient) SetRetryCount(count int) *PdfToImageClient {
    client.helper.setRetryCount(count)
    return client
}


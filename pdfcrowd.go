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
    "regexp"
)

const CLIENT_VERSION = "4.12.0"

type Error struct {
    message string
    code int
}

func (e Error) GetMessage() string {
    return e.message
}

func (e Error) GetCode() int {
    return e.code
}

func (e Error) Error() string {
    if e.code == 0 {
        return e.message
    }
    return fmt.Sprintf("%d - %s", e.code, e.message)
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
    outputSize int

    proxyHost string
    proxyPort int
    proxyUserName string
    proxyPassword string

    retryCount int
    retry int

    transport *http.Transport
}

func newConnectionHelper(userName, apiKey string) connectionHelper {
    helper := connectionHelper{userName: userName, apiKey: apiKey}
    helper.resetResponseData()
    helper.setUseHttp(false)
    helper.setUserAgent("pdfcrowd_go_client/4.12.0 (http://pdfcrowd.com)")
    helper.retryCount = 1
    return helper
}

func (helper *connectionHelper) resetResponseData() {
    helper.debugLogUrl = ""
    helper.credits = 999999
    helper.consumedCredits = 0
    helper.jobId = ""
    helper.pageCount = 0
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

func (helper *connectionHelper) getOutputSize() int {
    return helper.outputSize
}

func createInvalidValueMessage(value interface{}, field string, converter string, hint string, id string) string {
    message := fmt.Sprintf("Invalid value '%s' for the field '%s'.", value, field)
    if len(hint) > 0 {
        message += " " + hint
    }
    return message + " " + fmt.Sprintf("Details: https://www.pdfcrowd.com/doc/api/%s/go/#%s", converter, id)
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
        return nil, Error{message:"HTTPS over a proxy is not supported."}
    }

    helper.resetResponseData()

    for {
        body, contentType, err := encodeMultipartPostData(fields, files, rawData)
        if err != nil {
            return nil, err
        }

        request, err := http.NewRequest("POST", helper.apiUri, body)
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
                return nil, Error{
                    fmt.Sprintf("There was a problem connecting to Pdfcrowd servers over HTTPS:\n%s\nYou can still use the API over HTTP, you just need to add the following line right after Pdfcrowd client initialization:\nclient.setUseHttp(true)", err),
                    481 }
            }
            return nil, err
        }

        defer response.Body.Close()

        helper.debugLogUrl = getStringHeader(response, "X-Pdfcrowd-Debug-Log")
        helper.credits = getIntHeader(response, "X-Pdfcrowd-Remaining-Credits", 999999)
        helper.consumedCredits = getIntHeader(response, "X-Pdfcrowd-Consumed-Credits", -1)
        helper.jobId = getStringHeader(response, "X-Pdfcrowd-Job-Id")
        helper.pageCount = getIntHeader(response, "X-Pdfcrowd-Pages", -1)
        helper.outputSize = getIntHeader(response, "X-Pdfcrowd-Output-Size", -1)

        if (response.StatusCode == 502 || len(os.Getenv("PDFCROWD_UNIT_TEST_MODE")) > 0) && helper.retryCount > helper.retry {
            helper.retry++
            time.Sleep(time.Duration(helper.retry * 100) * time.Millisecond)
        } else {
            var respBody []byte
            respBody, err = ioutil.ReadAll(response.Body)
            if err != nil {
                return respBody, err
            }

            if response.StatusCode > 299 {
                return nil, Error{string(respBody), response.StatusCode}
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

// Constructor for the Pdfcrowd API client.
//
// userName - Your username at Pdfcrowd.
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
// url - The address of the web page to convert. The supported protocols are http:// and https://.
func (client *HtmlToPdfClient) ConvertUrl(url string) ([]byte, error) {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return nil, Error{createInvalidValueMessage(url, "url", "html-to-pdf", "The supported protocols are http:// and https://.", "convert_url"), 470}
    }
    
    client.fields["url"] = url
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert a web page and write the result to an output stream.
//
// url - The address of the web page to convert. The supported protocols are http:// and https://.
// outStream - The output stream that will contain the conversion output.
func (client *HtmlToPdfClient) ConvertUrlToStream(url string, outStream io.Writer) error {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return Error{createInvalidValueMessage(url, "url", "html-to-pdf", "The supported protocols are http:// and https://.", "convert_url_to_stream"), 470}
    }
    
    client.fields["url"] = url
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert a web page and write the result to a local file.
//
// url - The address of the web page to convert. The supported protocols are http:// and https://.
// filePath - The output file path. The string must not be empty.
func (client *HtmlToPdfClient) ConvertUrlToFile(url string, filePath string) error {
    if len(filePath) == 0 {
        return Error{createInvalidValueMessage(filePath, "file_path", "html-to-pdf", "The string must not be empty.", "convert_url_to_file"), 470}
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
        return nil, Error{createInvalidValueMessage(file, "file", "html-to-pdf", "The file must exist and not be empty.", "convert_file"), 470}
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
        return Error{createInvalidValueMessage(file, "file", "html-to-pdf", "The file must exist and not be empty.", "convert_file_to_stream"), 470}
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
        return Error{createInvalidValueMessage(filePath, "file_path", "html-to-pdf", "The string must not be empty.", "convert_file_to_file"), 470}
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
        return nil, Error{createInvalidValueMessage(text, "text", "html-to-pdf", "The string must not be empty.", "convert_string"), 470}
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
        return Error{createInvalidValueMessage(text, "text", "html-to-pdf", "The string must not be empty.", "convert_string_to_stream"), 470}
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
        return Error{createInvalidValueMessage(filePath, "file_path", "html-to-pdf", "The string must not be empty.", "convert_string_to_file"), 470}
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

// Set the output page size.
//
// pageSize - Allowed values are A2, A3, A4, A5, A6, Letter.
func (client *HtmlToPdfClient) SetPageSize(pageSize string) *HtmlToPdfClient {
    client.fields["page_size"] = pageSize
    return client
}

// Set the output page width. The safe maximum is 200in otherwise some PDF viewers may be unable to open the PDF.
//
// pageWidth - Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
func (client *HtmlToPdfClient) SetPageWidth(pageWidth string) *HtmlToPdfClient {
    client.fields["page_width"] = pageWidth
    return client
}

// Set the output page height. Use -1 for a single page PDF. The safe maximum is 200in otherwise some PDF viewers may be unable to open the PDF.
//
// pageHeight - Can be -1 or specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
func (client *HtmlToPdfClient) SetPageHeight(pageHeight string) *HtmlToPdfClient {
    client.fields["page_height"] = pageHeight
    return client
}

// Set the output page dimensions.
//
// width - Set the output page width. The safe maximum is 200in otherwise some PDF viewers may be unable to open the PDF. Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
// height - Set the output page height. Use -1 for a single page PDF. The safe maximum is 200in otherwise some PDF viewers may be unable to open the PDF. Can be -1 or specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
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
// marginTop - Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
func (client *HtmlToPdfClient) SetMarginTop(marginTop string) *HtmlToPdfClient {
    client.fields["margin_top"] = marginTop
    return client
}

// Set the output page right margin.
//
// marginRight - Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
func (client *HtmlToPdfClient) SetMarginRight(marginRight string) *HtmlToPdfClient {
    client.fields["margin_right"] = marginRight
    return client
}

// Set the output page bottom margin.
//
// marginBottom - Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
func (client *HtmlToPdfClient) SetMarginBottom(marginBottom string) *HtmlToPdfClient {
    client.fields["margin_bottom"] = marginBottom
    return client
}

// Set the output page left margin.
//
// marginLeft - Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
func (client *HtmlToPdfClient) SetMarginLeft(marginLeft string) *HtmlToPdfClient {
    client.fields["margin_left"] = marginLeft
    return client
}

// Disable page margins.
//
// noMargins - Set to true to disable margins.
func (client *HtmlToPdfClient) SetNoMargins(noMargins bool) *HtmlToPdfClient {
    client.fields["no_margins"] = strconv.FormatBool(noMargins)
    return client
}

// Set the output page margins.
//
// top - Set the output page top margin. Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
// right - Set the output page right margin. Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
// bottom - Set the output page bottom margin. Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
// left - Set the output page left margin. Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
func (client *HtmlToPdfClient) SetPageMargins(top string, right string, bottom string, left string) *HtmlToPdfClient {
    client.SetMarginTop(top)
    client.SetMarginRight(right)
    client.SetMarginBottom(bottom)
    client.SetMarginLeft(left)
    return client
}

// Load an HTML code from the specified URL and use it as the page header. The following classes can be used in the HTML. The content of the respective elements will be expanded as follows: pdfcrowd-page-count - the total page count of printed pages pdfcrowd-page-number - the current page number pdfcrowd-source-url - the source URL of a converted document The following attributes can be used: data-pdfcrowd-number-format - specifies the type of the used numerals Arabic numerals are used by default. Roman numerals can be generated by the roman and roman-lowercase values Example: <span class='pdfcrowd-page-number' data-pdfcrowd-number-format='roman'></span> data-pdfcrowd-placement - specifies where to place the source URL, allowed values: The URL is inserted to the content Example: <span class='pdfcrowd-source-url'></span> will produce <span>http://example.com</span> href - the URL is set to the href attribute Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href'>Link to source</a> will produce <a href='http://example.com'>Link to source</a> href-and-content - the URL is set to the href attribute and to the content Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href-and-content'></a> will produce <a href='http://example.com'>http://example.com</a>
//
// headerUrl - The supported protocols are http:// and https://.
func (client *HtmlToPdfClient) SetHeaderUrl(headerUrl string) *HtmlToPdfClient {
    client.fields["header_url"] = headerUrl
    return client
}

// Use the specified HTML code as the page header. The following classes can be used in the HTML. The content of the respective elements will be expanded as follows: pdfcrowd-page-count - the total page count of printed pages pdfcrowd-page-number - the current page number pdfcrowd-source-url - the source URL of a converted document The following attributes can be used: data-pdfcrowd-number-format - specifies the type of the used numerals Arabic numerals are used by default. Roman numerals can be generated by the roman and roman-lowercase values Example: <span class='pdfcrowd-page-number' data-pdfcrowd-number-format='roman'></span> data-pdfcrowd-placement - specifies where to place the source URL, allowed values: The URL is inserted to the content Example: <span class='pdfcrowd-source-url'></span> will produce <span>http://example.com</span> href - the URL is set to the href attribute Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href'>Link to source</a> will produce <a href='http://example.com'>Link to source</a> href-and-content - the URL is set to the href attribute and to the content Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href-and-content'></a> will produce <a href='http://example.com'>http://example.com</a>
//
// headerHtml - The string must not be empty.
func (client *HtmlToPdfClient) SetHeaderHtml(headerHtml string) *HtmlToPdfClient {
    client.fields["header_html"] = headerHtml
    return client
}

// Set the header height.
//
// headerHeight - Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
func (client *HtmlToPdfClient) SetHeaderHeight(headerHeight string) *HtmlToPdfClient {
    client.fields["header_height"] = headerHeight
    return client
}

// Load an HTML code from the specified URL and use it as the page footer. The following classes can be used in the HTML. The content of the respective elements will be expanded as follows: pdfcrowd-page-count - the total page count of printed pages pdfcrowd-page-number - the current page number pdfcrowd-source-url - the source URL of a converted document The following attributes can be used: data-pdfcrowd-number-format - specifies the type of the used numerals Arabic numerals are used by default. Roman numerals can be generated by the roman and roman-lowercase values Example: <span class='pdfcrowd-page-number' data-pdfcrowd-number-format='roman'></span> data-pdfcrowd-placement - specifies where to place the source URL, allowed values: The URL is inserted to the content Example: <span class='pdfcrowd-source-url'></span> will produce <span>http://example.com</span> href - the URL is set to the href attribute Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href'>Link to source</a> will produce <a href='http://example.com'>Link to source</a> href-and-content - the URL is set to the href attribute and to the content Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href-and-content'></a> will produce <a href='http://example.com'>http://example.com</a>
//
// footerUrl - The supported protocols are http:// and https://.
func (client *HtmlToPdfClient) SetFooterUrl(footerUrl string) *HtmlToPdfClient {
    client.fields["footer_url"] = footerUrl
    return client
}

// Use the specified HTML as the page footer. The following classes can be used in the HTML. The content of the respective elements will be expanded as follows: pdfcrowd-page-count - the total page count of printed pages pdfcrowd-page-number - the current page number pdfcrowd-source-url - the source URL of a converted document The following attributes can be used: data-pdfcrowd-number-format - specifies the type of the used numerals Arabic numerals are used by default. Roman numerals can be generated by the roman and roman-lowercase values Example: <span class='pdfcrowd-page-number' data-pdfcrowd-number-format='roman'></span> data-pdfcrowd-placement - specifies where to place the source URL, allowed values: The URL is inserted to the content Example: <span class='pdfcrowd-source-url'></span> will produce <span>http://example.com</span> href - the URL is set to the href attribute Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href'>Link to source</a> will produce <a href='http://example.com'>Link to source</a> href-and-content - the URL is set to the href attribute and to the content Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href-and-content'></a> will produce <a href='http://example.com'>http://example.com</a>
//
// footerHtml - The string must not be empty.
func (client *HtmlToPdfClient) SetFooterHtml(footerHtml string) *HtmlToPdfClient {
    client.fields["footer_html"] = footerHtml
    return client
}

// Set the footer height.
//
// footerHeight - Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
func (client *HtmlToPdfClient) SetFooterHeight(footerHeight string) *HtmlToPdfClient {
    client.fields["footer_height"] = footerHeight
    return client
}

// Set the page range to print.
//
// pages - A comma separated list of page numbers or ranges.
func (client *HtmlToPdfClient) SetPrintPageRange(pages string) *HtmlToPdfClient {
    client.fields["print_page_range"] = pages
    return client
}

// The page header is not printed on the specified pages.
//
// pages - List of physical page numbers. Negative numbers count backwards from the last page: -1 is the last page, -2 is the last but one page, and so on. A comma separated list of page numbers.
func (client *HtmlToPdfClient) SetExcludeHeaderOnPages(pages string) *HtmlToPdfClient {
    client.fields["exclude_header_on_pages"] = pages
    return client
}

// The page footer is not printed on the specified pages.
//
// pages - List of physical page numbers. Negative numbers count backwards from the last page: -1 is the last page, -2 is the last but one page, and so on. A comma separated list of page numbers.
func (client *HtmlToPdfClient) SetExcludeFooterOnPages(pages string) *HtmlToPdfClient {
    client.fields["exclude_footer_on_pages"] = pages
    return client
}

// Set an offset between physical and logical page numbers.
//
// offset - Integer specifying page offset.
func (client *HtmlToPdfClient) SetPageNumberingOffset(offset int) *HtmlToPdfClient {
    client.fields["page_numbering_offset"] = strconv.Itoa(offset)
    return client
}

// Set the top left X coordinate of the content area. It is relative to the top left X coordinate of the print area.
//
// contentAreaX - Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt). It may contain a negative value.
func (client *HtmlToPdfClient) SetContentAreaX(contentAreaX string) *HtmlToPdfClient {
    client.fields["content_area_x"] = contentAreaX
    return client
}

// Set the top left Y coordinate of the content area. It is relative to the top left Y coordinate of the print area.
//
// contentAreaY - Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt). It may contain a negative value.
func (client *HtmlToPdfClient) SetContentAreaY(contentAreaY string) *HtmlToPdfClient {
    client.fields["content_area_y"] = contentAreaY
    return client
}

// Set the width of the content area. It should be at least 1 inch.
//
// contentAreaWidth - Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
func (client *HtmlToPdfClient) SetContentAreaWidth(contentAreaWidth string) *HtmlToPdfClient {
    client.fields["content_area_width"] = contentAreaWidth
    return client
}

// Set the height of the content area. It should be at least 1 inch.
//
// contentAreaHeight - Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
func (client *HtmlToPdfClient) SetContentAreaHeight(contentAreaHeight string) *HtmlToPdfClient {
    client.fields["content_area_height"] = contentAreaHeight
    return client
}

// Set the content area position and size. The content area enables to specify a web page area to be converted.
//
// x - Set the top left X coordinate of the content area. It is relative to the top left X coordinate of the print area. Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt). It may contain a negative value.
// y - Set the top left Y coordinate of the content area. It is relative to the top left Y coordinate of the print area. Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt). It may contain a negative value.
// width - Set the width of the content area. It should be at least 1 inch. Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
// height - Set the height of the content area. It should be at least 1 inch. Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
func (client *HtmlToPdfClient) SetContentArea(x string, y string, width string, height string) *HtmlToPdfClient {
    client.SetContentAreaX(x)
    client.SetContentAreaY(y)
    client.SetContentAreaWidth(width)
    client.SetContentAreaHeight(height)
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
// dataEncoding - The data file encoding.
func (client *HtmlToPdfClient) SetDataEncoding(dataEncoding string) *HtmlToPdfClient {
    client.fields["data_encoding"] = dataEncoding
    return client
}

// Ignore undefined variables in the HTML template. The default mode is strict so any undefined variable causes the conversion to fail. You can use {% if variable is defined %} to check if the variable is defined.
//
// dataIgnoreUndefined - Set to true to ignore undefined variables.
func (client *HtmlToPdfClient) SetDataIgnoreUndefined(dataIgnoreUndefined bool) *HtmlToPdfClient {
    client.fields["data_ignore_undefined"] = strconv.FormatBool(dataIgnoreUndefined)
    return client
}

// Auto escape HTML symbols in the input data before placing them into the output.
//
// dataAutoEscape - Set to true to turn auto escaping on.
func (client *HtmlToPdfClient) SetDataAutoEscape(dataAutoEscape bool) *HtmlToPdfClient {
    client.fields["data_auto_escape"] = strconv.FormatBool(dataAutoEscape)
    return client
}

// Auto trim whitespace around each template command block.
//
// dataTrimBlocks - Set to true to turn auto trimming on.
func (client *HtmlToPdfClient) SetDataTrimBlocks(dataTrimBlocks bool) *HtmlToPdfClient {
    client.fields["data_trim_blocks"] = strconv.FormatBool(dataTrimBlocks)
    return client
}

// Set the advanced data options:csv_delimiter - The CSV data delimiter, the default is ,.xml_remove_root - Remove the root XML element from the input data.data_root - The name of the root element inserted into the input data without a root node (e.g. CSV), the default is data.
//
// dataOptions - Comma separated list of options.
func (client *HtmlToPdfClient) SetDataOptions(dataOptions string) *HtmlToPdfClient {
    client.fields["data_options"] = dataOptions
    return client
}

// Apply the first page of the watermark PDF to every page of the output PDF.
//
// pageWatermark - The file path to a local watermark PDF file. The file must exist and not be empty.
func (client *HtmlToPdfClient) SetPageWatermark(pageWatermark string) *HtmlToPdfClient {
    client.files["page_watermark"] = pageWatermark
    return client
}

// Load a watermark PDF from the specified URL and apply the first page of the watermark PDF to every page of the output PDF.
//
// pageWatermarkUrl - The supported protocols are http:// and https://.
func (client *HtmlToPdfClient) SetPageWatermarkUrl(pageWatermarkUrl string) *HtmlToPdfClient {
    client.fields["page_watermark_url"] = pageWatermarkUrl
    return client
}

// Apply each page of the specified watermark PDF to the corresponding page of the output PDF.
//
// multipageWatermark - The file path to a local watermark PDF file. The file must exist and not be empty.
func (client *HtmlToPdfClient) SetMultipageWatermark(multipageWatermark string) *HtmlToPdfClient {
    client.files["multipage_watermark"] = multipageWatermark
    return client
}

// Load a watermark PDF from the specified URL and apply each page of the specified watermark PDF to the corresponding page of the output PDF.
//
// multipageWatermarkUrl - The supported protocols are http:// and https://.
func (client *HtmlToPdfClient) SetMultipageWatermarkUrl(multipageWatermarkUrl string) *HtmlToPdfClient {
    client.fields["multipage_watermark_url"] = multipageWatermarkUrl
    return client
}

// Apply the first page of the specified PDF to the background of every page of the output PDF.
//
// pageBackground - The file path to a local background PDF file. The file must exist and not be empty.
func (client *HtmlToPdfClient) SetPageBackground(pageBackground string) *HtmlToPdfClient {
    client.files["page_background"] = pageBackground
    return client
}

// Load a background PDF from the specified URL and apply the first page of the background PDF to every page of the output PDF.
//
// pageBackgroundUrl - The supported protocols are http:// and https://.
func (client *HtmlToPdfClient) SetPageBackgroundUrl(pageBackgroundUrl string) *HtmlToPdfClient {
    client.fields["page_background_url"] = pageBackgroundUrl
    return client
}

// Apply each page of the specified PDF to the background of the corresponding page of the output PDF.
//
// multipageBackground - The file path to a local background PDF file. The file must exist and not be empty.
func (client *HtmlToPdfClient) SetMultipageBackground(multipageBackground string) *HtmlToPdfClient {
    client.files["multipage_background"] = multipageBackground
    return client
}

// Load a background PDF from the specified URL and apply each page of the specified background PDF to the corresponding page of the output PDF.
//
// multipageBackgroundUrl - The supported protocols are http:// and https://.
func (client *HtmlToPdfClient) SetMultipageBackgroundUrl(multipageBackgroundUrl string) *HtmlToPdfClient {
    client.fields["multipage_background_url"] = multipageBackgroundUrl
    return client
}

// The page background color in RGB or RGBA hexadecimal format. The color fills the entire page regardless of the margins.
//
// pageBackgroundColor - The value must be in RRGGBB or RRGGBBAA hexadecimal format.
func (client *HtmlToPdfClient) SetPageBackgroundColor(pageBackgroundColor string) *HtmlToPdfClient {
    client.fields["page_background_color"] = pageBackgroundColor
    return client
}

// Do not print the background graphics.
//
// noBackground - Set to true to disable the background graphics.
func (client *HtmlToPdfClient) SetNoBackground(noBackground bool) *HtmlToPdfClient {
    client.fields["no_background"] = strconv.FormatBool(noBackground)
    return client
}

// Do not execute JavaScript.
//
// disableJavascript - Set to true to disable JavaScript in web pages.
func (client *HtmlToPdfClient) SetDisableJavascript(disableJavascript bool) *HtmlToPdfClient {
    client.fields["disable_javascript"] = strconv.FormatBool(disableJavascript)
    return client
}

// Do not load images.
//
// disableImageLoading - Set to true to disable loading of images.
func (client *HtmlToPdfClient) SetDisableImageLoading(disableImageLoading bool) *HtmlToPdfClient {
    client.fields["disable_image_loading"] = strconv.FormatBool(disableImageLoading)
    return client
}

// Disable loading fonts from remote sources.
//
// disableRemoteFonts - Set to true disable loading remote fonts.
func (client *HtmlToPdfClient) SetDisableRemoteFonts(disableRemoteFonts bool) *HtmlToPdfClient {
    client.fields["disable_remote_fonts"] = strconv.FormatBool(disableRemoteFonts)
    return client
}

// Try to block ads. Enabling this option can produce smaller output and speed up the conversion.
//
// blockAds - Set to true to block ads in web pages.
func (client *HtmlToPdfClient) SetBlockAds(blockAds bool) *HtmlToPdfClient {
    client.fields["block_ads"] = strconv.FormatBool(blockAds)
    return client
}

// Set the default HTML content text encoding.
//
// defaultEncoding - The text encoding of the HTML content.
func (client *HtmlToPdfClient) SetDefaultEncoding(defaultEncoding string) *HtmlToPdfClient {
    client.fields["default_encoding"] = defaultEncoding
    return client
}

// Set the HTTP authentication user name.
//
// userName - The user name.
func (client *HtmlToPdfClient) SetHttpAuthUserName(userName string) *HtmlToPdfClient {
    client.fields["http_auth_user_name"] = userName
    return client
}

// Set the HTTP authentication password.
//
// password - The password.
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

// Use the print version of the page if available (@media print).
//
// usePrintMedia - Set to true to use the print version of the page.
func (client *HtmlToPdfClient) SetUsePrintMedia(usePrintMedia bool) *HtmlToPdfClient {
    client.fields["use_print_media"] = strconv.FormatBool(usePrintMedia)
    return client
}

// Do not send the X-Pdfcrowd HTTP header in Pdfcrowd HTTP requests.
//
// noXpdfcrowdHeader - Set to true to disable sending X-Pdfcrowd HTTP header.
func (client *HtmlToPdfClient) SetNoXpdfcrowdHeader(noXpdfcrowdHeader bool) *HtmlToPdfClient {
    client.fields["no_xpdfcrowd_header"] = strconv.FormatBool(noXpdfcrowdHeader)
    return client
}

// Set cookies that are sent in Pdfcrowd HTTP requests.
//
// cookies - The cookie string.
func (client *HtmlToPdfClient) SetCookies(cookies string) *HtmlToPdfClient {
    client.fields["cookies"] = cookies
    return client
}

// Do not allow insecure HTTPS connections.
//
// verifySslCertificates - Set to true to enable SSL certificate verification.
func (client *HtmlToPdfClient) SetVerifySslCertificates(verifySslCertificates bool) *HtmlToPdfClient {
    client.fields["verify_ssl_certificates"] = strconv.FormatBool(verifySslCertificates)
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

// Run a custom JavaScript after the document is loaded and ready to print. The script is intended for post-load DOM manipulation (add/remove elements, update CSS, ...). In addition to the standard browser APIs, the custom JavaScript code can use helper functions from our JavaScript library.
//
// customJavascript - A string containing a JavaScript code. The string must not be empty.
func (client *HtmlToPdfClient) SetCustomJavascript(customJavascript string) *HtmlToPdfClient {
    client.fields["custom_javascript"] = customJavascript
    return client
}

// Run a custom JavaScript right after the document is loaded. The script is intended for early DOM manipulation (add/remove elements, update CSS, ...). In addition to the standard browser APIs, the custom JavaScript code can use helper functions from our JavaScript library.
//
// onLoadJavascript - A string containing a JavaScript code. The string must not be empty.
func (client *HtmlToPdfClient) SetOnLoadJavascript(onLoadJavascript string) *HtmlToPdfClient {
    client.fields["on_load_javascript"] = onLoadJavascript
    return client
}

// Set a custom HTTP header that is sent in Pdfcrowd HTTP requests.
//
// customHttpHeader - A string containing the header name and value separated by a colon.
func (client *HtmlToPdfClient) SetCustomHttpHeader(customHttpHeader string) *HtmlToPdfClient {
    client.fields["custom_http_header"] = customHttpHeader
    return client
}

// Wait the specified number of milliseconds to finish all JavaScript after the document is loaded. Your API license defines the maximum wait time by "Max Delay" parameter.
//
// javascriptDelay - The number of milliseconds to wait. Must be a positive integer number or 0.
func (client *HtmlToPdfClient) SetJavascriptDelay(javascriptDelay int) *HtmlToPdfClient {
    client.fields["javascript_delay"] = strconv.Itoa(javascriptDelay)
    return client
}

// Convert only the specified element from the main document and its children. The element is specified by one or more CSS selectors. If the element is not found, the conversion fails. If multiple elements are found, the first one is used.
//
// selectors - One or more CSS selectors separated by commas. The string must not be empty.
func (client *HtmlToPdfClient) SetElementToConvert(selectors string) *HtmlToPdfClient {
    client.fields["element_to_convert"] = selectors
    return client
}

// Specify the DOM handling when only a part of the document is converted.
//
// mode - Allowed values are cut-out, remove-siblings, hide-siblings.
func (client *HtmlToPdfClient) SetElementToConvertMode(mode string) *HtmlToPdfClient {
    client.fields["element_to_convert_mode"] = mode
    return client
}

// Wait for the specified element in a source document. The element is specified by one or more CSS selectors. The element is searched for in the main document and all iframes. If the element is not found, the conversion fails. Your API license defines the maximum wait time by "Max Delay" parameter.
//
// selectors - One or more CSS selectors separated by commas. The string must not be empty.
func (client *HtmlToPdfClient) SetWaitForElement(selectors string) *HtmlToPdfClient {
    client.fields["wait_for_element"] = selectors
    return client
}

// Set the viewport width in pixels. The viewport is the user's visible area of the page.
//
// viewportWidth - The value must be in the range 96-65000.
func (client *HtmlToPdfClient) SetViewportWidth(viewportWidth int) *HtmlToPdfClient {
    client.fields["viewport_width"] = strconv.Itoa(viewportWidth)
    return client
}

// Set the viewport height in pixels. The viewport is the user's visible area of the page.
//
// viewportHeight - Must be a positive integer number.
func (client *HtmlToPdfClient) SetViewportHeight(viewportHeight int) *HtmlToPdfClient {
    client.fields["viewport_height"] = strconv.Itoa(viewportHeight)
    return client
}

// Set the viewport size. The viewport is the user's visible area of the page.
//
// width - Set the viewport width in pixels. The viewport is the user's visible area of the page. The value must be in the range 96-65000.
// height - Set the viewport height in pixels. The viewport is the user's visible area of the page. Must be a positive integer number.
func (client *HtmlToPdfClient) SetViewport(width int, height int) *HtmlToPdfClient {
    client.SetViewportWidth(width)
    client.SetViewportHeight(height)
    return client
}

// Set the rendering mode.
//
// renderingMode - The rendering mode. Allowed values are default, viewport.
func (client *HtmlToPdfClient) SetRenderingMode(renderingMode string) *HtmlToPdfClient {
    client.fields["rendering_mode"] = renderingMode
    return client
}

// Specifies the scaling mode used for fitting the HTML contents to the print area.
//
// smartScalingMode - The smart scaling mode. Allowed values are default, disabled, viewport-fit, content-fit, single-page-fit.
func (client *HtmlToPdfClient) SetSmartScalingMode(smartScalingMode string) *HtmlToPdfClient {
    client.fields["smart_scaling_mode"] = smartScalingMode
    return client
}

// Set the scaling factor (zoom) for the main page area.
//
// scaleFactor - The percentage value. The value must be in the range 10-500.
func (client *HtmlToPdfClient) SetScaleFactor(scaleFactor int) *HtmlToPdfClient {
    client.fields["scale_factor"] = strconv.Itoa(scaleFactor)
    return client
}

// Set the scaling factor (zoom) for the header and footer.
//
// headerFooterScaleFactor - The percentage value. The value must be in the range 10-500.
func (client *HtmlToPdfClient) SetHeaderFooterScaleFactor(headerFooterScaleFactor int) *HtmlToPdfClient {
    client.fields["header_footer_scale_factor"] = strconv.Itoa(headerFooterScaleFactor)
    return client
}

// Disable the intelligent shrinking strategy that tries to optimally fit the HTML contents to a PDF page.
//
// disableSmartShrinking - Set to true to disable the intelligent shrinking strategy.
func (client *HtmlToPdfClient) SetDisableSmartShrinking(disableSmartShrinking bool) *HtmlToPdfClient {
    client.fields["disable_smart_shrinking"] = strconv.FormatBool(disableSmartShrinking)
    return client
}

// Set the quality of embedded JPEG images. A lower quality results in a smaller PDF file but can lead to compression artifacts.
//
// jpegQuality - The percentage value. The value must be in the range 1-100.
func (client *HtmlToPdfClient) SetJpegQuality(jpegQuality int) *HtmlToPdfClient {
    client.fields["jpeg_quality"] = strconv.Itoa(jpegQuality)
    return client
}

// Specify which image types will be converted to JPEG. Converting lossless compression image formats (PNG, GIF, ...) to JPEG may result in a smaller PDF file.
//
// convertImagesToJpeg - The image category. Allowed values are none, opaque, all.
func (client *HtmlToPdfClient) SetConvertImagesToJpeg(convertImagesToJpeg string) *HtmlToPdfClient {
    client.fields["convert_images_to_jpeg"] = convertImagesToJpeg
    return client
}

// Set the DPI of images in PDF. A lower DPI may result in a smaller PDF file. If the specified DPI is higher than the actual image DPI, the original image DPI is retained (no upscaling is performed). Use 0 to leave the images unaltered.
//
// imageDpi - The DPI value. Must be a positive integer number or 0.
func (client *HtmlToPdfClient) SetImageDpi(imageDpi int) *HtmlToPdfClient {
    client.fields["image_dpi"] = strconv.Itoa(imageDpi)
    return client
}

// Create linearized PDF. This is also known as Fast Web View.
//
// linearize - Set to true to create linearized PDF.
func (client *HtmlToPdfClient) SetLinearize(linearize bool) *HtmlToPdfClient {
    client.fields["linearize"] = strconv.FormatBool(linearize)
    return client
}

// Encrypt the PDF. This prevents search engines from indexing the contents.
//
// encrypt - Set to true to enable PDF encryption.
func (client *HtmlToPdfClient) SetEncrypt(encrypt bool) *HtmlToPdfClient {
    client.fields["encrypt"] = strconv.FormatBool(encrypt)
    return client
}

// Protect the PDF with a user password. When a PDF has a user password, it must be supplied in order to view the document and to perform operations allowed by the access permissions.
//
// userPassword - The user password.
func (client *HtmlToPdfClient) SetUserPassword(userPassword string) *HtmlToPdfClient {
    client.fields["user_password"] = userPassword
    return client
}

// Protect the PDF with an owner password. Supplying an owner password grants unlimited access to the PDF including changing the passwords and access permissions.
//
// ownerPassword - The owner password.
func (client *HtmlToPdfClient) SetOwnerPassword(ownerPassword string) *HtmlToPdfClient {
    client.fields["owner_password"] = ownerPassword
    return client
}

// Disallow printing of the output PDF.
//
// noPrint - Set to true to set the no-print flag in the output PDF.
func (client *HtmlToPdfClient) SetNoPrint(noPrint bool) *HtmlToPdfClient {
    client.fields["no_print"] = strconv.FormatBool(noPrint)
    return client
}

// Disallow modification of the output PDF.
//
// noModify - Set to true to set the read-only only flag in the output PDF.
func (client *HtmlToPdfClient) SetNoModify(noModify bool) *HtmlToPdfClient {
    client.fields["no_modify"] = strconv.FormatBool(noModify)
    return client
}

// Disallow text and graphics extraction from the output PDF.
//
// noCopy - Set to true to set the no-copy flag in the output PDF.
func (client *HtmlToPdfClient) SetNoCopy(noCopy bool) *HtmlToPdfClient {
    client.fields["no_copy"] = strconv.FormatBool(noCopy)
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

// Specify the page layout to be used when the document is opened.
//
// pageLayout - Allowed values are single-page, one-column, two-column-left, two-column-right.
func (client *HtmlToPdfClient) SetPageLayout(pageLayout string) *HtmlToPdfClient {
    client.fields["page_layout"] = pageLayout
    return client
}

// Specify how the document should be displayed when opened.
//
// pageMode - Allowed values are full-screen, thumbnails, outlines.
func (client *HtmlToPdfClient) SetPageMode(pageMode string) *HtmlToPdfClient {
    client.fields["page_mode"] = pageMode
    return client
}

// Specify how the page should be displayed when opened.
//
// initialZoomType - Allowed values are fit-width, fit-height, fit-page.
func (client *HtmlToPdfClient) SetInitialZoomType(initialZoomType string) *HtmlToPdfClient {
    client.fields["initial_zoom_type"] = initialZoomType
    return client
}

// Display the specified page when the document is opened.
//
// initialPage - Must be a positive integer number.
func (client *HtmlToPdfClient) SetInitialPage(initialPage int) *HtmlToPdfClient {
    client.fields["initial_page"] = strconv.Itoa(initialPage)
    return client
}

// Specify the initial page zoom in percents when the document is opened.
//
// initialZoom - Must be a positive integer number.
func (client *HtmlToPdfClient) SetInitialZoom(initialZoom int) *HtmlToPdfClient {
    client.fields["initial_zoom"] = strconv.Itoa(initialZoom)
    return client
}

// Specify whether to hide the viewer application's tool bars when the document is active.
//
// hideToolbar - Set to true to hide tool bars.
func (client *HtmlToPdfClient) SetHideToolbar(hideToolbar bool) *HtmlToPdfClient {
    client.fields["hide_toolbar"] = strconv.FormatBool(hideToolbar)
    return client
}

// Specify whether to hide the viewer application's menu bar when the document is active.
//
// hideMenubar - Set to true to hide the menu bar.
func (client *HtmlToPdfClient) SetHideMenubar(hideMenubar bool) *HtmlToPdfClient {
    client.fields["hide_menubar"] = strconv.FormatBool(hideMenubar)
    return client
}

// Specify whether to hide user interface elements in the document's window (such as scroll bars and navigation controls), leaving only the document's contents displayed.
//
// hideWindowUi - Set to true to hide ui elements.
func (client *HtmlToPdfClient) SetHideWindowUi(hideWindowUi bool) *HtmlToPdfClient {
    client.fields["hide_window_ui"] = strconv.FormatBool(hideWindowUi)
    return client
}

// Specify whether to resize the document's window to fit the size of the first displayed page.
//
// fitWindow - Set to true to resize the window.
func (client *HtmlToPdfClient) SetFitWindow(fitWindow bool) *HtmlToPdfClient {
    client.fields["fit_window"] = strconv.FormatBool(fitWindow)
    return client
}

// Specify whether to position the document's window in the center of the screen.
//
// centerWindow - Set to true to center the window.
func (client *HtmlToPdfClient) SetCenterWindow(centerWindow bool) *HtmlToPdfClient {
    client.fields["center_window"] = strconv.FormatBool(centerWindow)
    return client
}

// Specify whether the window's title bar should display the document title. If false , the title bar should instead display the name of the PDF file containing the document.
//
// displayTitle - Set to true to display the title.
func (client *HtmlToPdfClient) SetDisplayTitle(displayTitle bool) *HtmlToPdfClient {
    client.fields["display_title"] = strconv.FormatBool(displayTitle)
    return client
}

// Set the predominant reading order for text to right-to-left. This option has no direct effect on the document's contents or page numbering but can be used to determine the relative positioning of pages when displayed side by side or printed n-up
//
// rightToLeft - Set to true to set right-to-left reading order.
func (client *HtmlToPdfClient) SetRightToLeft(rightToLeft bool) *HtmlToPdfClient {
    client.fields["right_to_left"] = strconv.FormatBool(rightToLeft)
    return client
}

// Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the getDebugLogUrl method or available in conversion statistics.
//
// debugLog - Set to true to enable the debug logging.
func (client *HtmlToPdfClient) SetDebugLog(debugLog bool) *HtmlToPdfClient {
    client.fields["debug_log"] = strconv.FormatBool(debugLog)
    return client
}

// Get the URL of the debug log for the last conversion.
func (client *HtmlToPdfClient) GetDebugLogUrl() string {
    return client.helper.getDebugLogUrl()
}

// Get the number of conversion credits available in your account.
// This method can only be called after a call to one of the convertXYZ methods.
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

// Get the total number of pages in the output document.
func (client *HtmlToPdfClient) GetPageCount() int {
    return client.helper.getPageCount()
}

// Get the size of the output in bytes.
func (client *HtmlToPdfClient) GetOutputSize() int {
    return client.helper.getOutputSize()
}

// Tag the conversion with a custom value. The tag is used in conversion statistics. A value longer than 32 characters is cut off.
//
// tag - A string with the custom tag.
func (client *HtmlToPdfClient) SetTag(tag string) *HtmlToPdfClient {
    client.fields["tag"] = tag
    return client
}

// A proxy server used by Pdfcrowd conversion process for accessing the source URLs with HTTP scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
//
// httpProxy - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
func (client *HtmlToPdfClient) SetHttpProxy(httpProxy string) *HtmlToPdfClient {
    client.fields["http_proxy"] = httpProxy
    return client
}

// A proxy server used by Pdfcrowd conversion process for accessing the source URLs with HTTPS scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
//
// httpsProxy - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
func (client *HtmlToPdfClient) SetHttpsProxy(httpsProxy string) *HtmlToPdfClient {
    client.fields["https_proxy"] = httpsProxy
    return client
}

// A client certificate to authenticate Pdfcrowd converter on your web server. The certificate is used for two-way SSL/TLS authentication and adds extra security.
//
// clientCertificate - The file must be in PKCS12 format. The file must exist and not be empty.
func (client *HtmlToPdfClient) SetClientCertificate(clientCertificate string) *HtmlToPdfClient {
    client.files["client_certificate"] = clientCertificate
    return client
}

// A password for PKCS12 file with a client certificate if it is needed.
//
// clientCertificatePassword -
func (client *HtmlToPdfClient) SetClientCertificatePassword(clientCertificatePassword string) *HtmlToPdfClient {
    client.fields["client_certificate_password"] = clientCertificatePassword
    return client
}

// Specifies if the client communicates over HTTP or HTTPS with Pdfcrowd API.
// Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
//
// useHttp - Set to true to use HTTP.
func (client *HtmlToPdfClient) SetUseHttp(useHttp bool) *HtmlToPdfClient {
    client.helper.setUseHttp(useHttp)
    return client
}

// Set a custom user agent HTTP header. It can be usefull if you are behind some proxy or firewall.
//
// userAgent - The user agent string.
func (client *HtmlToPdfClient) SetUserAgent(userAgent string) *HtmlToPdfClient {
    client.helper.setUserAgent(userAgent)
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

// Specifies the number of retries when the 502 HTTP status code is received. The 502 status code indicates a temporary network issue. This feature can be disabled by setting to 0.
//
// retryCount - Number of retries wanted.
func (client *HtmlToPdfClient) SetRetryCount(retryCount int) *HtmlToPdfClient {
    client.helper.setRetryCount(retryCount)
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

// Constructor for the Pdfcrowd API client.
//
// userName - Your username at Pdfcrowd.
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
// url - The address of the web page to convert. The supported protocols are http:// and https://.
func (client *HtmlToImageClient) ConvertUrl(url string) ([]byte, error) {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return nil, Error{createInvalidValueMessage(url, "url", "html-to-image", "The supported protocols are http:// and https://.", "convert_url"), 470}
    }
    
    client.fields["url"] = url
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert a web page and write the result to an output stream.
//
// url - The address of the web page to convert. The supported protocols are http:// and https://.
// outStream - The output stream that will contain the conversion output.
func (client *HtmlToImageClient) ConvertUrlToStream(url string, outStream io.Writer) error {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return Error{createInvalidValueMessage(url, "url", "html-to-image", "The supported protocols are http:// and https://.", "convert_url_to_stream"), 470}
    }
    
    client.fields["url"] = url
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert a web page and write the result to a local file.
//
// url - The address of the web page to convert. The supported protocols are http:// and https://.
// filePath - The output file path. The string must not be empty.
func (client *HtmlToImageClient) ConvertUrlToFile(url string, filePath string) error {
    if len(filePath) == 0 {
        return Error{createInvalidValueMessage(filePath, "file_path", "html-to-image", "The string must not be empty.", "convert_url_to_file"), 470}
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
        return nil, Error{createInvalidValueMessage(file, "file", "html-to-image", "The file must exist and not be empty.", "convert_file"), 470}
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
        return Error{createInvalidValueMessage(file, "file", "html-to-image", "The file must exist and not be empty.", "convert_file_to_stream"), 470}
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
        return Error{createInvalidValueMessage(filePath, "file_path", "html-to-image", "The string must not be empty.", "convert_file_to_file"), 470}
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
        return nil, Error{createInvalidValueMessage(text, "text", "html-to-image", "The string must not be empty.", "convert_string"), 470}
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
        return Error{createInvalidValueMessage(text, "text", "html-to-image", "The string must not be empty.", "convert_string_to_stream"), 470}
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
        return Error{createInvalidValueMessage(filePath, "file_path", "html-to-image", "The string must not be empty.", "convert_string_to_file"), 470}
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
// dataEncoding - The data file encoding.
func (client *HtmlToImageClient) SetDataEncoding(dataEncoding string) *HtmlToImageClient {
    client.fields["data_encoding"] = dataEncoding
    return client
}

// Ignore undefined variables in the HTML template. The default mode is strict so any undefined variable causes the conversion to fail. You can use {% if variable is defined %} to check if the variable is defined.
//
// dataIgnoreUndefined - Set to true to ignore undefined variables.
func (client *HtmlToImageClient) SetDataIgnoreUndefined(dataIgnoreUndefined bool) *HtmlToImageClient {
    client.fields["data_ignore_undefined"] = strconv.FormatBool(dataIgnoreUndefined)
    return client
}

// Auto escape HTML symbols in the input data before placing them into the output.
//
// dataAutoEscape - Set to true to turn auto escaping on.
func (client *HtmlToImageClient) SetDataAutoEscape(dataAutoEscape bool) *HtmlToImageClient {
    client.fields["data_auto_escape"] = strconv.FormatBool(dataAutoEscape)
    return client
}

// Auto trim whitespace around each template command block.
//
// dataTrimBlocks - Set to true to turn auto trimming on.
func (client *HtmlToImageClient) SetDataTrimBlocks(dataTrimBlocks bool) *HtmlToImageClient {
    client.fields["data_trim_blocks"] = strconv.FormatBool(dataTrimBlocks)
    return client
}

// Set the advanced data options:csv_delimiter - The CSV data delimiter, the default is ,.xml_remove_root - Remove the root XML element from the input data.data_root - The name of the root element inserted into the input data without a root node (e.g. CSV), the default is data.
//
// dataOptions - Comma separated list of options.
func (client *HtmlToImageClient) SetDataOptions(dataOptions string) *HtmlToImageClient {
    client.fields["data_options"] = dataOptions
    return client
}

// Do not print the background graphics.
//
// noBackground - Set to true to disable the background graphics.
func (client *HtmlToImageClient) SetNoBackground(noBackground bool) *HtmlToImageClient {
    client.fields["no_background"] = strconv.FormatBool(noBackground)
    return client
}

// Do not execute JavaScript.
//
// disableJavascript - Set to true to disable JavaScript in web pages.
func (client *HtmlToImageClient) SetDisableJavascript(disableJavascript bool) *HtmlToImageClient {
    client.fields["disable_javascript"] = strconv.FormatBool(disableJavascript)
    return client
}

// Do not load images.
//
// disableImageLoading - Set to true to disable loading of images.
func (client *HtmlToImageClient) SetDisableImageLoading(disableImageLoading bool) *HtmlToImageClient {
    client.fields["disable_image_loading"] = strconv.FormatBool(disableImageLoading)
    return client
}

// Disable loading fonts from remote sources.
//
// disableRemoteFonts - Set to true disable loading remote fonts.
func (client *HtmlToImageClient) SetDisableRemoteFonts(disableRemoteFonts bool) *HtmlToImageClient {
    client.fields["disable_remote_fonts"] = strconv.FormatBool(disableRemoteFonts)
    return client
}

// Try to block ads. Enabling this option can produce smaller output and speed up the conversion.
//
// blockAds - Set to true to block ads in web pages.
func (client *HtmlToImageClient) SetBlockAds(blockAds bool) *HtmlToImageClient {
    client.fields["block_ads"] = strconv.FormatBool(blockAds)
    return client
}

// Set the default HTML content text encoding.
//
// defaultEncoding - The text encoding of the HTML content.
func (client *HtmlToImageClient) SetDefaultEncoding(defaultEncoding string) *HtmlToImageClient {
    client.fields["default_encoding"] = defaultEncoding
    return client
}

// Set the HTTP authentication user name.
//
// userName - The user name.
func (client *HtmlToImageClient) SetHttpAuthUserName(userName string) *HtmlToImageClient {
    client.fields["http_auth_user_name"] = userName
    return client
}

// Set the HTTP authentication password.
//
// password - The password.
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

// Use the print version of the page if available (@media print).
//
// usePrintMedia - Set to true to use the print version of the page.
func (client *HtmlToImageClient) SetUsePrintMedia(usePrintMedia bool) *HtmlToImageClient {
    client.fields["use_print_media"] = strconv.FormatBool(usePrintMedia)
    return client
}

// Do not send the X-Pdfcrowd HTTP header in Pdfcrowd HTTP requests.
//
// noXpdfcrowdHeader - Set to true to disable sending X-Pdfcrowd HTTP header.
func (client *HtmlToImageClient) SetNoXpdfcrowdHeader(noXpdfcrowdHeader bool) *HtmlToImageClient {
    client.fields["no_xpdfcrowd_header"] = strconv.FormatBool(noXpdfcrowdHeader)
    return client
}

// Set cookies that are sent in Pdfcrowd HTTP requests.
//
// cookies - The cookie string.
func (client *HtmlToImageClient) SetCookies(cookies string) *HtmlToImageClient {
    client.fields["cookies"] = cookies
    return client
}

// Do not allow insecure HTTPS connections.
//
// verifySslCertificates - Set to true to enable SSL certificate verification.
func (client *HtmlToImageClient) SetVerifySslCertificates(verifySslCertificates bool) *HtmlToImageClient {
    client.fields["verify_ssl_certificates"] = strconv.FormatBool(verifySslCertificates)
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

// Run a custom JavaScript after the document is loaded and ready to print. The script is intended for post-load DOM manipulation (add/remove elements, update CSS, ...). In addition to the standard browser APIs, the custom JavaScript code can use helper functions from our JavaScript library.
//
// customJavascript - A string containing a JavaScript code. The string must not be empty.
func (client *HtmlToImageClient) SetCustomJavascript(customJavascript string) *HtmlToImageClient {
    client.fields["custom_javascript"] = customJavascript
    return client
}

// Run a custom JavaScript right after the document is loaded. The script is intended for early DOM manipulation (add/remove elements, update CSS, ...). In addition to the standard browser APIs, the custom JavaScript code can use helper functions from our JavaScript library.
//
// onLoadJavascript - A string containing a JavaScript code. The string must not be empty.
func (client *HtmlToImageClient) SetOnLoadJavascript(onLoadJavascript string) *HtmlToImageClient {
    client.fields["on_load_javascript"] = onLoadJavascript
    return client
}

// Set a custom HTTP header that is sent in Pdfcrowd HTTP requests.
//
// customHttpHeader - A string containing the header name and value separated by a colon.
func (client *HtmlToImageClient) SetCustomHttpHeader(customHttpHeader string) *HtmlToImageClient {
    client.fields["custom_http_header"] = customHttpHeader
    return client
}

// Wait the specified number of milliseconds to finish all JavaScript after the document is loaded. Your API license defines the maximum wait time by "Max Delay" parameter.
//
// javascriptDelay - The number of milliseconds to wait. Must be a positive integer number or 0.
func (client *HtmlToImageClient) SetJavascriptDelay(javascriptDelay int) *HtmlToImageClient {
    client.fields["javascript_delay"] = strconv.Itoa(javascriptDelay)
    return client
}

// Convert only the specified element from the main document and its children. The element is specified by one or more CSS selectors. If the element is not found, the conversion fails. If multiple elements are found, the first one is used.
//
// selectors - One or more CSS selectors separated by commas. The string must not be empty.
func (client *HtmlToImageClient) SetElementToConvert(selectors string) *HtmlToImageClient {
    client.fields["element_to_convert"] = selectors
    return client
}

// Specify the DOM handling when only a part of the document is converted.
//
// mode - Allowed values are cut-out, remove-siblings, hide-siblings.
func (client *HtmlToImageClient) SetElementToConvertMode(mode string) *HtmlToImageClient {
    client.fields["element_to_convert_mode"] = mode
    return client
}

// Wait for the specified element in a source document. The element is specified by one or more CSS selectors. The element is searched for in the main document and all iframes. If the element is not found, the conversion fails. Your API license defines the maximum wait time by "Max Delay" parameter.
//
// selectors - One or more CSS selectors separated by commas. The string must not be empty.
func (client *HtmlToImageClient) SetWaitForElement(selectors string) *HtmlToImageClient {
    client.fields["wait_for_element"] = selectors
    return client
}

// Set the output image width in pixels.
//
// screenshotWidth - The value must be in the range 96-65000.
func (client *HtmlToImageClient) SetScreenshotWidth(screenshotWidth int) *HtmlToImageClient {
    client.fields["screenshot_width"] = strconv.Itoa(screenshotWidth)
    return client
}

// Set the output image height in pixels. If it is not specified, actual document height is used.
//
// screenshotHeight - Must be a positive integer number.
func (client *HtmlToImageClient) SetScreenshotHeight(screenshotHeight int) *HtmlToImageClient {
    client.fields["screenshot_height"] = strconv.Itoa(screenshotHeight)
    return client
}

// Set the scaling factor (zoom) for the output image.
//
// scaleFactor - The percentage value. Must be a positive integer number.
func (client *HtmlToImageClient) SetScaleFactor(scaleFactor int) *HtmlToImageClient {
    client.fields["scale_factor"] = strconv.Itoa(scaleFactor)
    return client
}

// Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the getDebugLogUrl method or available in conversion statistics.
//
// debugLog - Set to true to enable the debug logging.
func (client *HtmlToImageClient) SetDebugLog(debugLog bool) *HtmlToImageClient {
    client.fields["debug_log"] = strconv.FormatBool(debugLog)
    return client
}

// Get the URL of the debug log for the last conversion.
func (client *HtmlToImageClient) GetDebugLogUrl() string {
    return client.helper.getDebugLogUrl()
}

// Get the number of conversion credits available in your account.
// This method can only be called after a call to one of the convertXYZ methods.
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

// Tag the conversion with a custom value. The tag is used in conversion statistics. A value longer than 32 characters is cut off.
//
// tag - A string with the custom tag.
func (client *HtmlToImageClient) SetTag(tag string) *HtmlToImageClient {
    client.fields["tag"] = tag
    return client
}

// A proxy server used by Pdfcrowd conversion process for accessing the source URLs with HTTP scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
//
// httpProxy - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
func (client *HtmlToImageClient) SetHttpProxy(httpProxy string) *HtmlToImageClient {
    client.fields["http_proxy"] = httpProxy
    return client
}

// A proxy server used by Pdfcrowd conversion process for accessing the source URLs with HTTPS scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
//
// httpsProxy - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
func (client *HtmlToImageClient) SetHttpsProxy(httpsProxy string) *HtmlToImageClient {
    client.fields["https_proxy"] = httpsProxy
    return client
}

// A client certificate to authenticate Pdfcrowd converter on your web server. The certificate is used for two-way SSL/TLS authentication and adds extra security.
//
// clientCertificate - The file must be in PKCS12 format. The file must exist and not be empty.
func (client *HtmlToImageClient) SetClientCertificate(clientCertificate string) *HtmlToImageClient {
    client.files["client_certificate"] = clientCertificate
    return client
}

// A password for PKCS12 file with a client certificate if it is needed.
//
// clientCertificatePassword -
func (client *HtmlToImageClient) SetClientCertificatePassword(clientCertificatePassword string) *HtmlToImageClient {
    client.fields["client_certificate_password"] = clientCertificatePassword
    return client
}

// Specifies if the client communicates over HTTP or HTTPS with Pdfcrowd API.
// Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
//
// useHttp - Set to true to use HTTP.
func (client *HtmlToImageClient) SetUseHttp(useHttp bool) *HtmlToImageClient {
    client.helper.setUseHttp(useHttp)
    return client
}

// Set a custom user agent HTTP header. It can be usefull if you are behind some proxy or firewall.
//
// userAgent - The user agent string.
func (client *HtmlToImageClient) SetUserAgent(userAgent string) *HtmlToImageClient {
    client.helper.setUserAgent(userAgent)
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

// Specifies the number of retries when the 502 HTTP status code is received. The 502 status code indicates a temporary network issue. This feature can be disabled by setting to 0.
//
// retryCount - Number of retries wanted.
func (client *HtmlToImageClient) SetRetryCount(retryCount int) *HtmlToImageClient {
    client.helper.setRetryCount(retryCount)
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

// Constructor for the Pdfcrowd API client.
//
// userName - Your username at Pdfcrowd.
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
// url - The address of the image to convert. The supported protocols are http:// and https://.
func (client *ImageToImageClient) ConvertUrl(url string) ([]byte, error) {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return nil, Error{createInvalidValueMessage(url, "url", "image-to-image", "The supported protocols are http:// and https://.", "convert_url"), 470}
    }
    
    client.fields["url"] = url
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert an image and write the result to an output stream.
//
// url - The address of the image to convert. The supported protocols are http:// and https://.
// outStream - The output stream that will contain the conversion output.
func (client *ImageToImageClient) ConvertUrlToStream(url string, outStream io.Writer) error {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return Error{createInvalidValueMessage(url, "url", "image-to-image", "The supported protocols are http:// and https://.", "convert_url_to_stream"), 470}
    }
    
    client.fields["url"] = url
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert an image and write the result to a local file.
//
// url - The address of the image to convert. The supported protocols are http:// and https://.
// filePath - The output file path. The string must not be empty.
func (client *ImageToImageClient) ConvertUrlToFile(url string, filePath string) error {
    if len(filePath) == 0 {
        return Error{createInvalidValueMessage(filePath, "file_path", "image-to-image", "The string must not be empty.", "convert_url_to_file"), 470}
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
// file - The path to a local file to convert. The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). The file must exist and not be empty.
func (client *ImageToImageClient) ConvertFile(file string) ([]byte, error) {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return nil, Error{createInvalidValueMessage(file, "file", "image-to-image", "The file must exist and not be empty.", "convert_file"), 470}
    }
    
    client.files["file"] = file
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert a local file and write the result to an output stream.
//
// file - The path to a local file to convert. The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). The file must exist and not be empty.
// outStream - The output stream that will contain the conversion output.
func (client *ImageToImageClient) ConvertFileToStream(file string, outStream io.Writer) error {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return Error{createInvalidValueMessage(file, "file", "image-to-image", "The file must exist and not be empty.", "convert_file_to_stream"), 470}
    }
    
    client.files["file"] = file
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert a local file and write the result to a local file.
//
// file - The path to a local file to convert. The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). The file must exist and not be empty.
// filePath - The output file path. The string must not be empty.
func (client *ImageToImageClient) ConvertFileToFile(file string, filePath string) error {
    if len(filePath) == 0 {
        return Error{createInvalidValueMessage(filePath, "file_path", "image-to-image", "The string must not be empty.", "convert_file_to_file"), 470}
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
        return Error{createInvalidValueMessage(filePath, "file_path", "image-to-image", "The string must not be empty.", "convert_raw_data_to_file"), 470}
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

// Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the getDebugLogUrl method or available in conversion statistics.
//
// debugLog - Set to true to enable the debug logging.
func (client *ImageToImageClient) SetDebugLog(debugLog bool) *ImageToImageClient {
    client.fields["debug_log"] = strconv.FormatBool(debugLog)
    return client
}

// Get the URL of the debug log for the last conversion.
func (client *ImageToImageClient) GetDebugLogUrl() string {
    return client.helper.getDebugLogUrl()
}

// Get the number of conversion credits available in your account.
// This method can only be called after a call to one of the convertXYZ methods.
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

// Tag the conversion with a custom value. The tag is used in conversion statistics. A value longer than 32 characters is cut off.
//
// tag - A string with the custom tag.
func (client *ImageToImageClient) SetTag(tag string) *ImageToImageClient {
    client.fields["tag"] = tag
    return client
}

// A proxy server used by Pdfcrowd conversion process for accessing the source URLs with HTTP scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
//
// httpProxy - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
func (client *ImageToImageClient) SetHttpProxy(httpProxy string) *ImageToImageClient {
    client.fields["http_proxy"] = httpProxy
    return client
}

// A proxy server used by Pdfcrowd conversion process for accessing the source URLs with HTTPS scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
//
// httpsProxy - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
func (client *ImageToImageClient) SetHttpsProxy(httpsProxy string) *ImageToImageClient {
    client.fields["https_proxy"] = httpsProxy
    return client
}

// Specifies if the client communicates over HTTP or HTTPS with Pdfcrowd API.
// Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
//
// useHttp - Set to true to use HTTP.
func (client *ImageToImageClient) SetUseHttp(useHttp bool) *ImageToImageClient {
    client.helper.setUseHttp(useHttp)
    return client
}

// Set a custom user agent HTTP header. It can be usefull if you are behind some proxy or firewall.
//
// userAgent - The user agent string.
func (client *ImageToImageClient) SetUserAgent(userAgent string) *ImageToImageClient {
    client.helper.setUserAgent(userAgent)
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

// Specifies the number of retries when the 502 HTTP status code is received. The 502 status code indicates a temporary network issue. This feature can be disabled by setting to 0.
//
// retryCount - Number of retries wanted.
func (client *ImageToImageClient) SetRetryCount(retryCount int) *ImageToImageClient {
    client.helper.setRetryCount(retryCount)
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

// Constructor for the Pdfcrowd API client.
//
// userName - Your username at Pdfcrowd.
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
// action - Allowed values are join, shuffle.
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
        return Error{createInvalidValueMessage(filePath, "file_path", "pdf-to-pdf", "The string must not be empty.", "convert_to_file"), 470}
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

// Add in-memory raw PDF data to the list of the input PDFs.Typical usage is for adding PDF created by another Pdfcrowd converter. Example in PHP: $clientPdf2Pdf->addPdfRawData($clientHtml2Pdf->convertUrl('http://www.example.com'));
//
// pdfRawData - The raw PDF data. The input data must be PDF content.
func (client *PdfToPdfClient) AddPdfRawData(pdfRawData []byte) *PdfToPdfClient {
    client.rawData["f_" + strconv.Itoa(client.fileId)] = pdfRawData
    client.fileId++
    return client
}

// Apply the first page of the watermark PDF to every page of the output PDF.
//
// pageWatermark - The file path to a local watermark PDF file. The file must exist and not be empty.
func (client *PdfToPdfClient) SetPageWatermark(pageWatermark string) *PdfToPdfClient {
    client.files["page_watermark"] = pageWatermark
    return client
}

// Load a watermark PDF from the specified URL and apply the first page of the watermark PDF to every page of the output PDF.
//
// pageWatermarkUrl - The supported protocols are http:// and https://.
func (client *PdfToPdfClient) SetPageWatermarkUrl(pageWatermarkUrl string) *PdfToPdfClient {
    client.fields["page_watermark_url"] = pageWatermarkUrl
    return client
}

// Apply each page of the specified watermark PDF to the corresponding page of the output PDF.
//
// multipageWatermark - The file path to a local watermark PDF file. The file must exist and not be empty.
func (client *PdfToPdfClient) SetMultipageWatermark(multipageWatermark string) *PdfToPdfClient {
    client.files["multipage_watermark"] = multipageWatermark
    return client
}

// Load a watermark PDF from the specified URL and apply each page of the specified watermark PDF to the corresponding page of the output PDF.
//
// multipageWatermarkUrl - The supported protocols are http:// and https://.
func (client *PdfToPdfClient) SetMultipageWatermarkUrl(multipageWatermarkUrl string) *PdfToPdfClient {
    client.fields["multipage_watermark_url"] = multipageWatermarkUrl
    return client
}

// Apply the first page of the specified PDF to the background of every page of the output PDF.
//
// pageBackground - The file path to a local background PDF file. The file must exist and not be empty.
func (client *PdfToPdfClient) SetPageBackground(pageBackground string) *PdfToPdfClient {
    client.files["page_background"] = pageBackground
    return client
}

// Load a background PDF from the specified URL and apply the first page of the background PDF to every page of the output PDF.
//
// pageBackgroundUrl - The supported protocols are http:// and https://.
func (client *PdfToPdfClient) SetPageBackgroundUrl(pageBackgroundUrl string) *PdfToPdfClient {
    client.fields["page_background_url"] = pageBackgroundUrl
    return client
}

// Apply each page of the specified PDF to the background of the corresponding page of the output PDF.
//
// multipageBackground - The file path to a local background PDF file. The file must exist and not be empty.
func (client *PdfToPdfClient) SetMultipageBackground(multipageBackground string) *PdfToPdfClient {
    client.files["multipage_background"] = multipageBackground
    return client
}

// Load a background PDF from the specified URL and apply each page of the specified background PDF to the corresponding page of the output PDF.
//
// multipageBackgroundUrl - The supported protocols are http:// and https://.
func (client *PdfToPdfClient) SetMultipageBackgroundUrl(multipageBackgroundUrl string) *PdfToPdfClient {
    client.fields["multipage_background_url"] = multipageBackgroundUrl
    return client
}

// Create linearized PDF. This is also known as Fast Web View.
//
// linearize - Set to true to create linearized PDF.
func (client *PdfToPdfClient) SetLinearize(linearize bool) *PdfToPdfClient {
    client.fields["linearize"] = strconv.FormatBool(linearize)
    return client
}

// Encrypt the PDF. This prevents search engines from indexing the contents.
//
// encrypt - Set to true to enable PDF encryption.
func (client *PdfToPdfClient) SetEncrypt(encrypt bool) *PdfToPdfClient {
    client.fields["encrypt"] = strconv.FormatBool(encrypt)
    return client
}

// Protect the PDF with a user password. When a PDF has a user password, it must be supplied in order to view the document and to perform operations allowed by the access permissions.
//
// userPassword - The user password.
func (client *PdfToPdfClient) SetUserPassword(userPassword string) *PdfToPdfClient {
    client.fields["user_password"] = userPassword
    return client
}

// Protect the PDF with an owner password. Supplying an owner password grants unlimited access to the PDF including changing the passwords and access permissions.
//
// ownerPassword - The owner password.
func (client *PdfToPdfClient) SetOwnerPassword(ownerPassword string) *PdfToPdfClient {
    client.fields["owner_password"] = ownerPassword
    return client
}

// Disallow printing of the output PDF.
//
// noPrint - Set to true to set the no-print flag in the output PDF.
func (client *PdfToPdfClient) SetNoPrint(noPrint bool) *PdfToPdfClient {
    client.fields["no_print"] = strconv.FormatBool(noPrint)
    return client
}

// Disallow modification of the output PDF.
//
// noModify - Set to true to set the read-only only flag in the output PDF.
func (client *PdfToPdfClient) SetNoModify(noModify bool) *PdfToPdfClient {
    client.fields["no_modify"] = strconv.FormatBool(noModify)
    return client
}

// Disallow text and graphics extraction from the output PDF.
//
// noCopy - Set to true to set the no-copy flag in the output PDF.
func (client *PdfToPdfClient) SetNoCopy(noCopy bool) *PdfToPdfClient {
    client.fields["no_copy"] = strconv.FormatBool(noCopy)
    return client
}

// Specify the page layout to be used when the document is opened.
//
// pageLayout - Allowed values are single-page, one-column, two-column-left, two-column-right.
func (client *PdfToPdfClient) SetPageLayout(pageLayout string) *PdfToPdfClient {
    client.fields["page_layout"] = pageLayout
    return client
}

// Specify how the document should be displayed when opened.
//
// pageMode - Allowed values are full-screen, thumbnails, outlines.
func (client *PdfToPdfClient) SetPageMode(pageMode string) *PdfToPdfClient {
    client.fields["page_mode"] = pageMode
    return client
}

// Specify how the page should be displayed when opened.
//
// initialZoomType - Allowed values are fit-width, fit-height, fit-page.
func (client *PdfToPdfClient) SetInitialZoomType(initialZoomType string) *PdfToPdfClient {
    client.fields["initial_zoom_type"] = initialZoomType
    return client
}

// Display the specified page when the document is opened.
//
// initialPage - Must be a positive integer number.
func (client *PdfToPdfClient) SetInitialPage(initialPage int) *PdfToPdfClient {
    client.fields["initial_page"] = strconv.Itoa(initialPage)
    return client
}

// Specify the initial page zoom in percents when the document is opened.
//
// initialZoom - Must be a positive integer number.
func (client *PdfToPdfClient) SetInitialZoom(initialZoom int) *PdfToPdfClient {
    client.fields["initial_zoom"] = strconv.Itoa(initialZoom)
    return client
}

// Specify whether to hide the viewer application's tool bars when the document is active.
//
// hideToolbar - Set to true to hide tool bars.
func (client *PdfToPdfClient) SetHideToolbar(hideToolbar bool) *PdfToPdfClient {
    client.fields["hide_toolbar"] = strconv.FormatBool(hideToolbar)
    return client
}

// Specify whether to hide the viewer application's menu bar when the document is active.
//
// hideMenubar - Set to true to hide the menu bar.
func (client *PdfToPdfClient) SetHideMenubar(hideMenubar bool) *PdfToPdfClient {
    client.fields["hide_menubar"] = strconv.FormatBool(hideMenubar)
    return client
}

// Specify whether to hide user interface elements in the document's window (such as scroll bars and navigation controls), leaving only the document's contents displayed.
//
// hideWindowUi - Set to true to hide ui elements.
func (client *PdfToPdfClient) SetHideWindowUi(hideWindowUi bool) *PdfToPdfClient {
    client.fields["hide_window_ui"] = strconv.FormatBool(hideWindowUi)
    return client
}

// Specify whether to resize the document's window to fit the size of the first displayed page.
//
// fitWindow - Set to true to resize the window.
func (client *PdfToPdfClient) SetFitWindow(fitWindow bool) *PdfToPdfClient {
    client.fields["fit_window"] = strconv.FormatBool(fitWindow)
    return client
}

// Specify whether to position the document's window in the center of the screen.
//
// centerWindow - Set to true to center the window.
func (client *PdfToPdfClient) SetCenterWindow(centerWindow bool) *PdfToPdfClient {
    client.fields["center_window"] = strconv.FormatBool(centerWindow)
    return client
}

// Specify whether the window's title bar should display the document title. If false , the title bar should instead display the name of the PDF file containing the document.
//
// displayTitle - Set to true to display the title.
func (client *PdfToPdfClient) SetDisplayTitle(displayTitle bool) *PdfToPdfClient {
    client.fields["display_title"] = strconv.FormatBool(displayTitle)
    return client
}

// Set the predominant reading order for text to right-to-left. This option has no direct effect on the document's contents or page numbering but can be used to determine the relative positioning of pages when displayed side by side or printed n-up
//
// rightToLeft - Set to true to set right-to-left reading order.
func (client *PdfToPdfClient) SetRightToLeft(rightToLeft bool) *PdfToPdfClient {
    client.fields["right_to_left"] = strconv.FormatBool(rightToLeft)
    return client
}

// Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the getDebugLogUrl method or available in conversion statistics.
//
// debugLog - Set to true to enable the debug logging.
func (client *PdfToPdfClient) SetDebugLog(debugLog bool) *PdfToPdfClient {
    client.fields["debug_log"] = strconv.FormatBool(debugLog)
    return client
}

// Get the URL of the debug log for the last conversion.
func (client *PdfToPdfClient) GetDebugLogUrl() string {
    return client.helper.getDebugLogUrl()
}

// Get the number of conversion credits available in your account.
// This method can only be called after a call to one of the convertXYZ methods.
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

// Get the total number of pages in the output document.
func (client *PdfToPdfClient) GetPageCount() int {
    return client.helper.getPageCount()
}

// Get the size of the output in bytes.
func (client *PdfToPdfClient) GetOutputSize() int {
    return client.helper.getOutputSize()
}

// Tag the conversion with a custom value. The tag is used in conversion statistics. A value longer than 32 characters is cut off.
//
// tag - A string with the custom tag.
func (client *PdfToPdfClient) SetTag(tag string) *PdfToPdfClient {
    client.fields["tag"] = tag
    return client
}

// Specifies if the client communicates over HTTP or HTTPS with Pdfcrowd API.
// Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
//
// useHttp - Set to true to use HTTP.
func (client *PdfToPdfClient) SetUseHttp(useHttp bool) *PdfToPdfClient {
    client.helper.setUseHttp(useHttp)
    return client
}

// Set a custom user agent HTTP header. It can be usefull if you are behind some proxy or firewall.
//
// userAgent - The user agent string.
func (client *PdfToPdfClient) SetUserAgent(userAgent string) *PdfToPdfClient {
    client.helper.setUserAgent(userAgent)
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

// Specifies the number of retries when the 502 HTTP status code is received. The 502 status code indicates a temporary network issue. This feature can be disabled by setting to 0.
//
// retryCount - Number of retries wanted.
func (client *PdfToPdfClient) SetRetryCount(retryCount int) *PdfToPdfClient {
    client.helper.setRetryCount(retryCount)
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

// Constructor for the Pdfcrowd API client.
//
// userName - Your username at Pdfcrowd.
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
// url - The address of the image to convert. The supported protocols are http:// and https://.
func (client *ImageToPdfClient) ConvertUrl(url string) ([]byte, error) {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return nil, Error{createInvalidValueMessage(url, "url", "image-to-pdf", "The supported protocols are http:// and https://.", "convert_url"), 470}
    }
    
    client.fields["url"] = url
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert an image and write the result to an output stream.
//
// url - The address of the image to convert. The supported protocols are http:// and https://.
// outStream - The output stream that will contain the conversion output.
func (client *ImageToPdfClient) ConvertUrlToStream(url string, outStream io.Writer) error {
    re, _ := regexp.Compile("(?i)^https?://.*$")
    if !re.MatchString(url) {
        return Error{createInvalidValueMessage(url, "url", "image-to-pdf", "The supported protocols are http:// and https://.", "convert_url_to_stream"), 470}
    }
    
    client.fields["url"] = url
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert an image and write the result to a local file.
//
// url - The address of the image to convert. The supported protocols are http:// and https://.
// filePath - The output file path. The string must not be empty.
func (client *ImageToPdfClient) ConvertUrlToFile(url string, filePath string) error {
    if len(filePath) == 0 {
        return Error{createInvalidValueMessage(filePath, "file_path", "image-to-pdf", "The string must not be empty.", "convert_url_to_file"), 470}
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
// file - The path to a local file to convert. The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). The file must exist and not be empty.
func (client *ImageToPdfClient) ConvertFile(file string) ([]byte, error) {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return nil, Error{createInvalidValueMessage(file, "file", "image-to-pdf", "The file must exist and not be empty.", "convert_file"), 470}
    }
    
    client.files["file"] = file
    return client.helper.post(client.fields, client.files, client.rawData, nil)
}

// Convert a local file and write the result to an output stream.
//
// file - The path to a local file to convert. The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). The file must exist and not be empty.
// outStream - The output stream that will contain the conversion output.
func (client *ImageToPdfClient) ConvertFileToStream(file string, outStream io.Writer) error {
    if stat, err := os.Stat(file); err != nil || stat.Size() == 0 {
        return Error{createInvalidValueMessage(file, "file", "image-to-pdf", "The file must exist and not be empty.", "convert_file_to_stream"), 470}
    }
    
    client.files["file"] = file
    _, err := client.helper.post(client.fields, client.files, client.rawData, outStream)
    return err
}

// Convert a local file and write the result to a local file.
//
// file - The path to a local file to convert. The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). The file must exist and not be empty.
// filePath - The output file path. The string must not be empty.
func (client *ImageToPdfClient) ConvertFileToFile(file string, filePath string) error {
    if len(filePath) == 0 {
        return Error{createInvalidValueMessage(filePath, "file_path", "image-to-pdf", "The string must not be empty.", "convert_file_to_file"), 470}
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
        return Error{createInvalidValueMessage(filePath, "file_path", "image-to-pdf", "The string must not be empty.", "convert_raw_data_to_file"), 470}
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

// Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the getDebugLogUrl method or available in conversion statistics.
//
// debugLog - Set to true to enable the debug logging.
func (client *ImageToPdfClient) SetDebugLog(debugLog bool) *ImageToPdfClient {
    client.fields["debug_log"] = strconv.FormatBool(debugLog)
    return client
}

// Get the URL of the debug log for the last conversion.
func (client *ImageToPdfClient) GetDebugLogUrl() string {
    return client.helper.getDebugLogUrl()
}

// Get the number of conversion credits available in your account.
// This method can only be called after a call to one of the convertXYZ methods.
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

// Tag the conversion with a custom value. The tag is used in conversion statistics. A value longer than 32 characters is cut off.
//
// tag - A string with the custom tag.
func (client *ImageToPdfClient) SetTag(tag string) *ImageToPdfClient {
    client.fields["tag"] = tag
    return client
}

// A proxy server used by Pdfcrowd conversion process for accessing the source URLs with HTTP scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
//
// httpProxy - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
func (client *ImageToPdfClient) SetHttpProxy(httpProxy string) *ImageToPdfClient {
    client.fields["http_proxy"] = httpProxy
    return client
}

// A proxy server used by Pdfcrowd conversion process for accessing the source URLs with HTTPS scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
//
// httpsProxy - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
func (client *ImageToPdfClient) SetHttpsProxy(httpsProxy string) *ImageToPdfClient {
    client.fields["https_proxy"] = httpsProxy
    return client
}

// Specifies if the client communicates over HTTP or HTTPS with Pdfcrowd API.
// Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
//
// useHttp - Set to true to use HTTP.
func (client *ImageToPdfClient) SetUseHttp(useHttp bool) *ImageToPdfClient {
    client.helper.setUseHttp(useHttp)
    return client
}

// Set a custom user agent HTTP header. It can be usefull if you are behind some proxy or firewall.
//
// userAgent - The user agent string.
func (client *ImageToPdfClient) SetUserAgent(userAgent string) *ImageToPdfClient {
    client.helper.setUserAgent(userAgent)
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

// Specifies the number of retries when the 502 HTTP status code is received. The 502 status code indicates a temporary network issue. This feature can be disabled by setting to 0.
//
// retryCount - Number of retries wanted.
func (client *ImageToPdfClient) SetRetryCount(retryCount int) *ImageToPdfClient {
    client.helper.setRetryCount(retryCount)
    return client
}


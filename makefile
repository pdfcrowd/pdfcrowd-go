VERSION = 5.8.0
DIR_NAME := pdfcrowd-5.8.0

dist: dist/pdfcrowd-$(VERSION)-go.zip

dist/pdfcrowd-$(VERSION)-go.zip:
	@mkdir -p dist
	@cd dist && mkdir -p $(DIR_NAME) && cp ../pdfcrowd.go $(DIR_NAME) && zip pdfcrowd-$(VERSION)-go.zip $(DIR_NAME)/*

publish: clean dist

.PHONY: clean
clean:
	rm -rf dist/* ./test_files/out/go_*.pdf

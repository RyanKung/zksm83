PAPER := zksm83
BUILD := build
OUTPUT := ../output/pdf

.PHONY: all clean

all: $(OUTPUT)/$(PAPER).pdf

$(OUTPUT)/$(PAPER).pdf: $(PAPER).tex references.bib
	mkdir -p $(BUILD) $(OUTPUT)
	latexmk -pdf -interaction=nonstopmode -halt-on-error -file-line-error \
		-outdir=$(BUILD) $(PAPER).tex
	cp $(BUILD)/$(PAPER).pdf $@

clean:
	latexmk -C -outdir=$(BUILD) $(PAPER).tex
	rm -rf $(BUILD)

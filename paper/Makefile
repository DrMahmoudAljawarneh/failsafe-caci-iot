LATEXMK ?= latexmk

pdf:
	$(LATEXMK) -pdf -bibtex-cond1 -interaction=nonstopmode -file-line-error main.tex

clean:
	$(LATEXMK) -C

.PHONY: pdf clean

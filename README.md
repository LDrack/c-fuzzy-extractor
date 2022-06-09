# c-fuzzy-extractor
A fuzzy extractor written in C, based on a Python implementation by C. Yagemann, who did all the heavy lifting. Please see his original implementation (with stellar documentation) at https://github.com/carter-yagemann/python-fuzzy-extractor

The underlying construction is based on Canetti et al. 2016 (Reusable Fuzzy Extractors for Low-Entropy Distributions). As such, this fuzzy extractor does not employ ECC, but rather relies on digital lockers.

I developed this tool in the course of my master thesis at FH Hagenberg, focusing on SRAM PUFs. I used it to demonstrate that low-cost authentication is possible with SRAM PUFs. Sadly, this fuzzy extractor, being based on digital lockers, produces a substantial amount of helper data. It produces so much helper data, in fact, that it becomes unusable with larger (i.e. realistically sized) SRAM fingerprints.

An improved approach to the digital locker fuzzy extractor exists: please see Cheon et al. 2018 (A Reusable Fuzzy Extractor with Practical Storage Size). Using their threshold method, one could reduce the size of helper data by over 98%.

---

**(C) Embedded Systems Lab / FH Hagenberg**

All rights reserved.

This document contains proprietary information belonging to Research & Development FH OÖ Forschungs und Entwicklungs GmbH. Using, passing on and copying of this document or parts of it is generally not permitted without prior written authorization.

info(at)embedded-lab.at

https://www.embedded-lab.at/

The research on which this source code is based has been partly funded by BMK, BMDW, and the State of Upper Austria in the frame of the COMET Programme managed by FFG.

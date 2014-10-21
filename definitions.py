#!/usr/bin/env python

#If a token requires another token then please specify it before the needed token

def definitions(self):
    definitions = {
        '@DOMAIN@' : "DOMAIN.NAME.COM",
        '@DC_LOWER@' : str(self.params.farm).lower(),
        '@DC_UPPER@' : self.params.farm,
    }
    return definitions

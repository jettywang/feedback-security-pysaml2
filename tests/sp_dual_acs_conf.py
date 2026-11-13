from pathutils import full_path
from pathutils import xmlsec_path

from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_HTTP_REDIRECT


CONFIG = {
    "entityid": "urn:mace:example.com:saml:dual:sp",
    "name": "urn:mace:example.com:saml:dual:sp",
    "description": "SP with two assertion consumer services on different bindings",
    "service": {
        "sp": {
            "endpoints": {
                "assertion_consumer_service": [
                    ("https://dual.sp.example.org/acs/post", BINDING_HTTP_POST),
                    ("https://dual.sp.example.org/acs/redirect", BINDING_HTTP_REDIRECT),
                ],
            },
            "idp": ["urn:mace:example.com:saml:roland:idp"],
        }
    },
    "debug": 1,
    "key_file": full_path("test.key"),
    "cert_file": full_path("test.pem"),
    "xmlsec_binary": xmlsec_path,
    "metadata": [
        {
            "class": "saml2.mdstore.MetaDataFile",
            "metadata": [(full_path("idp.xml"),)],
        }
    ],
    "attribute_map_dir": full_path("attributemaps"),
}

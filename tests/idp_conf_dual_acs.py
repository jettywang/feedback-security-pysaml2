from pathutils import full_path
from pathutils import xmlsec_path

from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_HTTP_REDIRECT
from saml2.saml import NAME_FORMAT_URI


BASE = "http://localhost:8088"

CONFIG = {
    "entityid": "urn:mace:example.com:saml:roland:idp",
    "name": "Rolands IdP",
    "service": {
        "idp": {
            "endpoints": {
                "single_sign_on_service": [
                    (f"{BASE}/sso", BINDING_HTTP_REDIRECT),
                    (f"{BASE}/sso/post", BINDING_HTTP_POST),
                ],
            },
            "policy": {
                "default": {
                    "lifetime": {"minutes": 15},
                    "attribute_restrictions": None,  # means all I have
                    "name_form": NAME_FORMAT_URI,
                },
            },
            "subject_data": full_path("subject_data_dual.db"),
        },
    },
    "debug": 1,
    "key_file": full_path("test.key"),
    "cert_file": full_path("test.pem"),
    "xmlsec_binary": xmlsec_path,
    "metadata": [
        {
            "class": "saml2.mdstore.MetaDataFile",
            "metadata": [
                (full_path("metadata_sp_dual_acs.xml"),),
            ],
        }
    ],
    "attribute_map_dir": full_path("attributemaps"),
}

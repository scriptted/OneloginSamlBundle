<?php

namespace Hslavich\OneloginSamlBundle\Service;

class IDPMetadataService
{
    protected $container;

    function __construct($container) {
        $this->container = $container;
    }

    public function getSSODataByEntity($entityID = null){
        $reader = new \XMLReader();

        $path = $this->container->get('kernel')->locateResource('@HslavichOneloginSamlBundle/Resources/metadata/IDPMetadata.xml');
        $reader->open($path);

        while ($reader->read()) {
            switch ($reader->nodeType) {
                case (\XMLREADER::ELEMENT):
                    if ($reader->localName == "EntityDescriptor") {
                        if ($reader->getAttribute("entityID") == $entityID) {
                            $node = $reader->expand();
                            $idpProperties = $this->xml_to_array($node);

                            $cert = trim($idpProperties['md:IDPSSODescriptor']['md:KeyDescriptor']['ds:KeyInfo']['ds:X509Data']['ds:X509Certificate']);

                            foreach ($idpProperties['md:IDPSSODescriptor']['md:SingleSignOnService'] as $singleSignOnService) {
                                if($singleSignOnService['@attributes']['Binding'] == 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'){
                                    $ssoUrl = $singleSignOnService['@attributes']['Location'];
                                }
                            }

                            foreach ($idpProperties['md:IDPSSODescriptor']['md:SingleLogoutService'] as $singleLogoutService) {
                                if($singleLogoutService['@attributes']['Binding'] == 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'){
                                    $sloUrl = $singleLogoutService['@attributes']['Location'];
                                }
                            }

                            $idp = array(
                                'entityId' => $entityID,
                                'singleSignOnService' => array (
                            		'url' => isset($ssoUrl) ? $ssoUrl : null
                                ),
                                'singleLogoutService' => array (
                                    'url' => isset($ssoUrl) ? $sloUrl : null
                                ),
                                'x509cert' => $cert,
                            );
                        }
                    }
            }
        }

        return $idp;
    }

    private function xml_to_array($root) {
        $result = array();

        if ($root->hasAttributes()) {
            $attrs = $root->attributes;
            foreach ($attrs as $attr) {
                $result['@attributes'][$attr->name] = $attr->value;
            }
        }

        if ($root->hasChildNodes()) {
            $children = $root->childNodes;
            if ($children->length == 1) {
                $child = $children->item(0);
                if ($child->nodeType == XML_TEXT_NODE) {
                    $result['_value'] = $child->nodeValue;
                    return count($result) == 1
                        ? $result['_value']
                        : $result;
                }
            }
            $groups = array();
            foreach ($children as $child) {
                if (!isset($result[$child->nodeName])) {
                    $result[$child->nodeName] = $this->xml_to_array($child);
                } else {
                    if (!isset($groups[$child->nodeName])) {
                        $result[$child->nodeName] = array($result[$child->nodeName]);
                        $groups[$child->nodeName] = 1;
                    }
                    $result[$child->nodeName][] = $this->xml_to_array($child);
                }
            }
        }

        return $result;
    }

}

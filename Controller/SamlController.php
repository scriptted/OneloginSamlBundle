<?php

namespace Hslavich\OneloginSamlBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;

class SamlController extends Controller
{
    public function loginAction(Request $request)
    {
        $session = $this->get('session');

        $auth = $this->get('onelogin_auth');

        $IDPentityID = $request->query->get('entityID', null);

        $samlSettings = $auth->getSettings();

        $metadataProvider = $this->get('hslavich_onelogin_saml.idp_metadata');

        if($IDPentityID){
            $session->set('IDPentityID', $IDPentityID);

            $metadata = $metadataProvider->getSSODataByEntity($IDPentityID);

            $session->set('idp', $metadata);

            $samlSettings->setIDPData($metadata);

            $auth->setSettings($samlSettings);

            $ssoBuiltUrl = $auth->login(null, array(), false, false, true);

            $session->set('AuthNRequestID', $auth->getLastRequestID());
            header('Pragma: no-cache');
            header('Cache-Control: no-cache, must-revalidate');
            header('Location: ' . $ssoBuiltUrl);
            exit();
        }

        $SPentityID = $samlSettings->getSPData()['entityId'];

        header('Location: '.$samlSettings->getDSData()['url'].'?entityID='.urlencode($SPentityID).'&return='.urlencode("http://127.0.0.1:8000/saml/login"));
        exit();
    }

    public function metadataAction()
    {
        $auth = $this->get('onelogin_auth');
        $metadata = $auth->getSettings()->getSPMetadata();

        $response = new Response($metadata);
        $response->headers->set('Content-Type', 'xml');

        return $response;
    }

    public function assertionConsumerServiceAction()
    {
        throw new \RuntimeException('You must configure the check path to be handled by the firewall.');
    }

    public function singleLogoutServiceAction()
    {
        throw new \RuntimeException('You must activate the logout in your security firewall configuration.');
    }
}

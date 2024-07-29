<?php

namespace Appwrite\Auth\OAuth2;

use Appwrite\Auth\OAuth2;

// Reference Material
// https://developers.pipedrive.com/docs/api/v1/Oauth

class Pipedrive extends OAuth2
{
    private string $endpoint = 'https://oauth.pipedrive.com';
    protected array $user = [];
    protected array $tokens = [];
    protected array $scopes = [
        'base',
        'users:read'
    ];

    public function getName(): string
    {
        return 'pipedrive';
    }

    public function getLoginURL(): string
    {
        return $this->endpoint . '/oauth/authorize?' . \http_build_query([
            'client_id' => $this->appID,
            'redirect_uri' => $this->callback,
            'state' => \json_encode($this->state)
        ]);
    }

    protected function getTokens(string $code): array
    {
        $headers = [
            'Authorization: Basic ' . \base64_encode($this->appID . ':' . $this->appSecret),
            'Content-Type: application/x-www-form-urlencoded'
        ];
        if (empty($this->tokens)) {
            $this->tokens = \json_decode($this->request(
                'POST',
                $this->endpoint . '/oauth/token',
                $headers,
                \http_build_query([
                    'grant_type' => "authorization_code",
                    'code' => $code,
                    'redirect_uri' => $this->callback
                ])
            ), true);

            $this->refreshToken = $this->tokens['refresh_token'];
        }
        /*
            access_token
            token_type
            refresh_token
            scope
            expires_in
            api_domain
        */
        return $this->tokens;
    }

    public function refreshTokens(string $refreshToken): array
    {
        $headers = [
            'Authorization: Basic ' . \base64_encode($this->appID . ':' . $this->appSecret),
            'Content-Type: application/x-www-form-urlencoded'
        ];
        if (empty($this->tokens)) {
            $this->tokens = \json_decode($this->request(
                'POST',
                $this->endpoint . '/oauth/token',
                $headers,
                \http_build_query([
                    'grant_type' => "refresh_token",
                    'refresh_token' => $this->tokens['refresh_token']
                ])
            ), true);
        }
        /*
            access_token
            token_type
            refresh_token
            scope
            expires_in
            api_domain
        */
        return $this->tokens;
    }

    public function getUserID(string $accessToken): string
    {
        $user = $this->getUser($accessToken);
        if ($user['success'] && isset($user['data']['id'])) {
            return $user['data']['id'];
        }

        return '';
    }

    public function getUserEmail(string $accessToken): string
    {
        $user = $this->getUser($accessToken);
        if ($user['success'] && isset($user['data']['email'])) {
            return $user['data']['email'];
        }

        return '';
    }

    public function isEmailVerified(string $accessToken): bool
    {
        $user = $this->getUser($accessToken);
        if ($user['success'] && isset($user['data']['activated'])) {
            return $user['data']['activated'];
        }

        return false;
    }
    
    public function getUserName(string $accessToken): string
    {
        $user = $this->getUser($accessToken);
        if ($user['success'] && isset($user['data']['name'])) {
           return $user['data']['name'];
        }

        return '';
    }

    protected function getUser(string $accessToken): array
    {
        $header = [
            'Content-Type: application/json',
            'Authorization: Bearer ' . \urlencode($this->tokens['access_token']),
        ];
        if (empty($this->user)) {
            $user = $this->request(
                'GET',
                $this->tokens['api_domain'] . '.pipedrive.com/api/v1/users/me',
                $header
            );
            $this->user = \json_decode($user, true);
        }

        return $this->user;
    }
}
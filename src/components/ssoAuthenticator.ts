import * as moment from "moment";
import { Utils } from "../utils";
import { IAuthenticator, AccessToken } from "./../authentication";
import { HttpClient, HttpHeader } from "@paperbits/common/http";

const accessTokenSetting = "accessToken";
const serverTokenSetting = "serverToken";

export class SsoAuthenticator implements IAuthenticator {
    constructor( private httpClient: HttpClient){}
    
    public async getAccessToken(): Promise<string> {
        let accessToken = null;

        if (location.pathname.startsWith("/signin-sso")) {
            const token = decodeURIComponent(location.href.split("?token=").pop());
            accessToken = `SharedAccessSignature ${token}`;
            sessionStorage.setItem(accessTokenSetting, accessToken);
            window.location.assign("/");
        } else {
            accessToken = sessionStorage.getItem(accessTokenSetting);
            if (!accessToken) {
                try {
                    const response = await this.httpClient.send<string>({ url: "/token", method: "GET" });
                    if (response.statusCode === 200) {
                        const token = response.toText();
                        accessToken = `SharedAccessSignature ${token}`;
                        sessionStorage.setItem(accessTokenSetting, accessToken);
                        sessionStorage.setItem(serverTokenSetting, accessToken);
                    }
                } catch (error) {
                    console.error("Error on token request: ", error);
                }
            } else {
                if (this.isTokenExpired(accessToken)) {
                    await this.clearAccessToken();
                    return null;
                }
            }
        }

        return accessToken;
    }

    public setAccessToken(accessToken: string): Promise<void> {
        return new Promise<void>((resolve) => {
            const ssoRequired = !sessionStorage.getItem(accessTokenSetting);
            sessionStorage.setItem(accessTokenSetting, decodeURIComponent(accessToken));

            if (ssoRequired) {
                window.location.assign(`/signin-sso?token=${accessToken.replace("SharedAccessSignature ", "")}`);
            }
            else {
                resolve();
            }
        });
    }

    public async refreshAccessTokenFromHeader(responseHeaders: HttpHeader[] = []): Promise<string> {
        const accessTokenHeader = responseHeaders.find(x => x.name.toLowerCase() === "ocp-apim-sas-token");
        if (accessTokenHeader && accessTokenHeader.value) {
            const regex = /token=\"(.*)",refresh/gm;
            const match = regex.exec(accessTokenHeader.value);

            if (!match || match.length < 2) {
                console.error(`Token format is not valid.`);
            }

            const accessToken = `SharedAccessSignature ${accessTokenHeader.value}`;
            const current = sessionStorage.getItem(accessTokenSetting);
            if (current !== accessToken) {
                sessionStorage.setItem(accessTokenSetting, accessToken);

                try {
                    await this.httpClient.send<any>({ url: "/sso-refresh", method: "GET", headers: [{ name: "Authorization", value: accessToken }] });
                    sessionStorage.setItem(serverTokenSetting, accessToken);
                } catch (error) {
                    console.error("Error on sso-refresh: ", error);
                }                
                
                return accessToken;
            }
        }
        
        const serverToken = sessionStorage.getItem(serverTokenSetting);
        if (!serverToken) {            
            const clientToken = sessionStorage.getItem(accessTokenSetting);
            if (clientToken) {
                if (this.isTokenExpired(clientToken)) {
                    await this.clearAccessToken(true);
                } else {
                    try {
                        await this.httpClient.send<any>({ url: "/sso-refresh", method: "GET", headers: [{ name: "Authorization", value: clientToken }] });
                        sessionStorage.setItem(serverTokenSetting, clientToken);
                    } catch (error) {
                        console.error("Error on sso-refresh: ", error);
                    }  
                }
            }
        }
        return undefined;
    }

    public async clearAccessToken(cleanOnlyClient?: boolean): Promise<void> {
        const token = sessionStorage.getItem(accessTokenSetting);
        if (token) {
            sessionStorage.removeItem(accessTokenSetting);
            if (!cleanOnlyClient) {
                try {
                    await this.httpClient.send<any>({ url: "/signout", method: "GET", headers: [{ name: "Authorization", value: token }] });
                    sessionStorage.removeItem(serverTokenSetting);
                } catch (error) {
                    console.error("Error on clearAccessToken: ", error);
                }
            }
        }
    }

    public async isAuthenticated(): Promise<boolean> {
        const accessToken = await this.getAccessToken();
        return !!accessToken;
    }

    public parseAccessToken(token: string): AccessToken {
        if (!token) {
            throw new Error("Access token is missing.");
        }

        let accessToken: AccessToken;

        if (token.startsWith("Bearer ")) {
            accessToken = this.parseBearerToken(token.replace("Bearer ", ""));
            return accessToken;
        }

        if (token.startsWith("SharedAccessSignature ")) {
            accessToken = this.parseSharedAccessSignature(token.replace("SharedAccessSignature ", ""));
            return accessToken;
        }

        throw new Error(`Access token format is not valid. Please use "Bearer" or "SharedAccessSignature".`);
    }

    private parseSharedAccessSignature(fullAccessToken: string): AccessToken {
        let accessToken = fullAccessToken;
        const refreshRegex = /token=\"(.*)",refresh/gm;
        const refreshMatch = refreshRegex.exec(fullAccessToken);
        if (!refreshMatch || refreshMatch.length < 2) {
            console.warn(`Token is not full.`);
        } else {
            accessToken = refreshMatch[1];
        } 

        const regex = /^[\w\-]*\&(\d*)\&/gm;
        const match = regex.exec(accessToken);

        if (!match || match.length < 2) {
            throw new Error(`SharedAccessSignature token format is not valid.`);
        }

        const dateTime = match[1];
        const dateTimeIso = `${dateTime.substr(0, 8)} ${dateTime.substr(8, 4)}`;
        const expirationDateUtc = moment(dateTimeIso).toDate();

        return { type: "SharedAccessSignature", expires: expirationDateUtc, value: accessToken };
    }

    private parseBearerToken(accessToken: string): AccessToken {
        const decodedToken = Utils.parseJwt(accessToken);
        const exp = moment(decodedToken.exp).toDate();

        return { type: "Bearer", expires: exp, value: accessToken };
    }

    private isTokenExpired(accessToken: string): boolean {
        const parsedToken = this.parseAccessToken(accessToken);
        const now = Utils.getUtcDateTime();

        return (now > parsedToken.expires);
    }
}
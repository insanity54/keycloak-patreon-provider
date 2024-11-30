package org.keycloak.social.patreon;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.Option;
import java.util.List;

public class PatreonIdentityProvider extends AbstractOAuth2IdentityProvider<PatreonIdentityProviderConfig>
    implements SocialIdentityProvider<PatreonIdentityProviderConfig> {

    private static final Logger log = Logger.getLogger(PatreonIdentityProvider.class);

    private List<String> extractCurrentlyEntitledTiers(JsonNode profile) {
        try {
            // Configure JsonPath to handle missing fields gracefully
            Configuration config = Configuration.defaultConfiguration().addOptions(Option.DEFAULT_PATH_LEAF_TO_NULL);

            // Convert JsonNode to Object for JsonPath parsing
            // Object jsonDocument = config.jsonProvider().parse(profile.toString());
            ObjectNode profileObject = (ObjectNode) profile;
            
            // config.jsonProvider().parse(profileObject);
            return JsonPath.read(profileObject, "$.included[?(@.type=='member')].relationships.currently_entitled_tiers.data[*].id");

        } catch (Exception e) {
            log.warn("Error extracting currently entitled tiers", e);
            return List.of(); // Return an empty list in case of errors
        }
    }

    public static final String AUTH_URL = "https://www.patreon.com/oauth2/authorize";
    public static final String TOKEN_URL = "https://www.patreon.com/api/oauth2/token";
    public static final String PROFILE_URL = "https://www.patreon.com/api/oauth2/v2/identity?fields%5Buser%5D=about,created,email,first_name,full_name,image_url,last_name,social_connections,thumb_url,url,vanity&include=memberships,memberships.currently_entitled_tiers,memberships.currently_entitled_tiers.benefits,memberships.campaign";
    public static final String DEFAULT_SCOPE = "identity";


    public PatreonIdentityProvider(KeycloakSession session, PatreonIdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
        config.setUserInfoUrl(PROFILE_URL);
    }

    @Override
    protected boolean supportsExternalExchange() {
        return true;
    }

    @Override
    protected String getProfileEndpointForValidation(EventBuilder event) {
        return PROFILE_URL;
    }

    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
        BrokeredIdentityContext user = new BrokeredIdentityContext(getJsonProperty(profile.path("data"), "id"), getConfig());

        user.setUsername(getJsonProperty(profile.path("data").path("attributes"), "full_name"));
        user.setIdp(this);

        // ((ObjectNode)profile).put("test", "testing123-PatreonIdentityProvider-test-profile-monkeypatch");


        // Extract currently entitled tiers using JSONPath
        List<String> entitledTiers = extractCurrentlyEntitledTiers(profile);
        // Ensure profile is an ObjectNode before trying to mutate it
        if (profile instanceof ObjectNode) {
            ObjectNode objectNode = (ObjectNode) profile;

            // Patch or add a new field (example: "test" with "testing123")
            objectNode.put("test", "testing123-PatreonIdentityProvider-test-profile-monkeypatch");

            // Optionally add the list of entitled tiers (assuming you're patching the profile with it)
            if (!entitledTiers.isEmpty()) {
                objectNode.putPOJO("currently_entitled_tiers", entitledTiers);
            }
        }

        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());

        return user;
    }

    @Override
    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
        log.debug("doGetFederatedIdentity()");

        JsonNode profile;

        try {
            profile = SimpleHttp.doGet(PROFILE_URL, session).header("Authorization", "Bearer " + accessToken).asJson();
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not obtain user profile from patreon.", e);
        }

        return extractIdentityFromProfile(null, profile);
    }

    @Override
    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }
}

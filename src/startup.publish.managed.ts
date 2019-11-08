// import { AzureBlobStorage } from "@paperbits/azure";
import { InversifyInjector } from "@paperbits/common/injection";
import { IPublisher } from "@paperbits/common/publishing";
import { CoreModule } from "@paperbits/core/core.module";
import { CorePublishModule } from "@paperbits/core/core.publish.module";
import { StyleModule } from "@paperbits/styles/styles.module";
import { ProseMirrorModule } from "@paperbits/prosemirror/prosemirror.module";
import { StaticSettingsProvider } from "./components/staticSettingsProvider";
import { ApimPublishModule } from "./apim.publish.module";

/* Allowing self-signed certificates for HTTP requests */
process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0";

export class Publisher {
    constructor(
        private readonly configuration: any,
        private readonly outputBlobStorage: any
    ) {
        if (!configuration) {
            console.log("configuration parameter is required");
            return;
        }
    }

    public async run(): Promise<void> {
        /* Reading settings from configuration file */
        const settingsProvider = new StaticSettingsProvider({
            managementApiUrl: this.configuration.managementApiUrl,
            managementApiVersion: this.configuration.managementApiVersion,
            managementApiAccessToken: this.configuration.managementApiAccessToken,
            blobStorageContainer: this.configuration.inputStorageContainer,
            blobStorageConnectionString: this.configuration.inputStorageConnectionString,
            environment: "publishing",
            backendUrl: "http://127.0.0.1:30006"
        });

        /* Initializing dependency injection container */
        const injector = new InversifyInjector();
        injector.bindModule(new CoreModule());
        injector.bindModule(new CorePublishModule());
        injector.bindModule(new StyleModule());
        injector.bindModule(new ProseMirrorModule());
        injector.bindModule(new ApimPublishModule());
        injector.bindInstance("settingsProvider", settingsProvider);
        injector.bindInstance("outputBlobStorage", this.outputBlobStorage);
        injector.resolve("autostart");

        /* Bulding dependency injection container */
        const publisher = injector.resolve<IPublisher>("sitePublisher");

        /* Running actual publishing */
        await publisher.publish();
    }
}

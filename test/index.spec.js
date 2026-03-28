import {expect} from "chai";
import {
    explicitTransferCheck,
    filterMoreSpecific,
    lessSpecific,
    prefixLookup,
    prefixLookupArin,
    rirServers,
    whois
} from "../src/index.js";

const LIVE_RIR_FIXTURES = [
    {
        name: "ripe",
        server: "whois.ripe.net",
        query: "83.231.214.0/24",
        expectedInet: "83.231.214.0 - 83.231.214.255"
    },
    {
        name: "arin",
        server: "whois.arin.net",
        query: "8.8.8.0/24",
        expectedInet: "8.8.8.0 - 8.8.8.255"
    },
    {
        name: "lacnic",
        server: "whois.lacnic.net",
        query: "181.64.132.0/24",
        expectedInet: "181.64.128.0/18"
    },
    {
        name: "apnic",
        server: "whois.apnic.net",
        query: "1.1.1.0/24",
        expectedInet: "1.1.1.0 - 1.1.1.255"
    },
    {
        name: "afrinic",
        server: "whois.afrinic.net",
        query: "196.223.14.0/24",
        expectedInet: "196.223.0.0 - 196.223.31.255"
    }
];

const hasAnyFields = (answers) => answers
    .flatMap((answer) => answer.data || [])
    .some((items) => Array.isArray(items) && items.length > 0);

const inetKeys = new Set(["inetnum", "inet6num", "netrange"]);

const collectInetValues = (answer) => (answer.data || [])
    .flatMap((items) => items || [])
    .filter((item) => inetKeys.has(item.key.toLowerCase()))
    .map((item) => String(item.value || "").trim())
    .filter(Boolean);

const normalizeInet = (value) => String(value || "")
    .trim()
    .replace(/\s+/g, " ")
    .toLowerCase();

const hasExpectedInet = (answer, expectedInet) => {
    const expected = normalizeInet(expectedInet);
    return collectInetValues(answer)
        .map((value) => normalizeInet(value))
        .includes(expected);
};

describe("whois-wrapper live test suite", function () {
    this.timeout(180000);

    it("exports the 5 known RIR servers", () => {
        expect(Object.keys(rirServers)).to.have.members(["ripe", "arin", "lacnic", "apnic", "afrinic"]);
        expect(Object.values(rirServers)).to.have.members(LIVE_RIR_FIXTURES.map((i) => i.server));
    });

    it("whois performs a real lookup and parses records", async () => {
        const answers = await whois({
            query: "8.8.8.0/24",
            servers: ["whois.arin.net"],
            flag: "h",
            timeout: 20000
        });

        expect(answers).to.be.an("array").that.is.not.empty;
        expect(answers[0].server).to.equal("whois.arin.net");
        expect(answers[0].data).to.be.an("array").that.is.not.empty;
    });

    it("whois respects fields filter", async () => {
        const allowed = new Set(["netrange", "netname", "orgname", "country"]);
        const answers = await whois({
            query: "8.8.8.0/24",
            servers: ["whois.arin.net"],
            fields: Array.from(allowed),
            flag: "h",
            timeout: 20000
        });

        expect(answers).to.be.an("array").that.is.not.empty;

        for (const answer of answers) {
            for (const items of answer.data || []) {
                for (const item of items) {
                    expect(allowed.has(item.key.toLowerCase())).to.equal(true);
                }
            }
        }
    });

    it("whois reaches 4 (no arin) RIRs with live resources", async () => {
        const four = LIVE_RIR_FIXTURES.filter(({name}) => name !== "arin");
        const results = await Promise.all(four.map((fixture) => whois({
            query: fixture.query,
            servers: [fixture.server],
            flag: "h",
            timeout: 25000
        })));

        const flattened = results.flat();
        const servers = new Set(flattened.map((i) => i.server));

        expect(Array.from(servers)).to.have.members(four.map((i) => i.server));
        expect(hasAnyFields(flattened)).to.equal(true);

        for (let i = 0; i < four.length; i++) {
            const fixture = four[i];
            const answerForFixture = (results[i] || []).find((item) => item.server === fixture.server);

            expect(answerForFixture, `missing answer for ${fixture.server}`).to.exist;
            expect(hasExpectedInet(answerForFixture, fixture.expectedInet), `${fixture.server} did not return expected inet value ${fixture.expectedInet}`).to.equal(true);
        }
    });

    it("filterMoreSpecific returns the most specific answer", () => {
        const answers = [
            {
                server: "parent",
                data: [[{key: "inetnum", value: "10.0.0.0 - 10.0.0.255"}]]
            },
            {
                server: "child",
                data: [[{key: "inetnum", value: "10.0.0.128 - 10.0.0.255"}]]
            }
        ];

        const selected = filterMoreSpecific(answers, "10.0.0.200/32");
        expect(selected).to.be.an("array").that.is.not.empty;
        expect(selected.some((i) => i.server === "child")).to.equal(true);
    });

    it("prefixLookupArin resolves ARIN data via live whois", async () => {
        const answers = await prefixLookupArin({query: "8.8.8.0/24", flag: "h", timeout: 25000});

        expect(answers).to.be.an("array");
        expect(answers.length).to.be.greaterThan(0);
        expect(answers.some((i) => i.server === "whois.arin.net")).to.equal(true);
    });

    it("prefixLookup resolves data and applies field filters", async () => {
        const answers = await prefixLookup({query: "8.8.8.0/24", fields: ["netrange", "netname", "orgname"], flag: "h"});

        expect(answers).to.be.an("array");
        expect(answers.length).to.be.greaterThan(0);

        const allowed = new Set(["netrange", "netname", "orgname"]);
        for (const answer of answers) {
            for (const items of answer.data || []) {
                for (const item of items) {
                    expect(allowed.has(item.key.toLowerCase())).to.equal(true);
                }
            }
        }
    });

    it("explicitTransferCheck queries all RIR servers", async () => {
        const checks = await Promise.all(LIVE_RIR_FIXTURES.map((fixture) => explicitTransferCheck({
            query: fixture.query,
            flag: "h",
            timeout: 25000
        })));

        expect(checks).to.be.an("array").with.lengthOf(LIVE_RIR_FIXTURES.length);
        for (const result of checks) {
            expect(result).to.be.an("array").with.lengthOf(5);
        }

        const observedServers = new Set(
            checks
                .flat()
                .flat()
                .map((i) => i.server)
                .filter(Boolean)
        );

        expect(Array.from(observedServers)).to.have.members(LIVE_RIR_FIXTURES.map((i) => i.server));
    });

    it("lessSpecific evaluates prefixes using live lookups", async () => {
        const answers = await lessSpecific(
            {query: "8.8.8.0/24", flag: "h"},
            (data) => data.some((item) => item?.server === "whois.arin.net"),
            24
        );

        expect(answers).to.be.an("array");
        expect(answers.length).to.be.greaterThan(0);
    });
});

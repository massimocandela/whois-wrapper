import ipUtils from "ip-sub";
import LongestPrefixMatch from "longest-prefix-match";
import batchPromises from "batch-promises";
import {execSync} from "child_process";

const rirs = {
    "ripe": "whois.ripe.net",
    "arin": "whois.arin.net",
    "lacnic": "whois.lacnic.net",
    "apnic": "whois.apnic.net",
    "afrinic": "whois.afrinic.net"
};

const filterFields = (fields = [], answers) => {

    if (fields?.length > 0) {
        fields = fields.map(i => i.toLowerCase());

        for (let answer of answers) {
            const out = [];

            for (let items of answer.data ?? []) {
                const filtered = items.filter(i => fields.includes(i.key.toLowerCase()));

                if (filtered.length > 0) {
                    out.push(filtered);
                }
            }

            answer.data = out;
        }

    }

    return answers;
};

export const filterMoreSpecific = (answers, prefix) => {
    if (answers.length > 1) {
        const index = new LongestPrefixMatch();

        for (let answer of answers) {
            for (let items of answer?.data ?? []) {
                const inetnums = items?.filter(n => ["inetnum", "inet6num", "netrange"].includes(n.key.toLowerCase())).map(i => i.value);

                if (inetnums.length) {
                    for (let inetnum of inetnums) {
                        for (let p of rangeToPrefix(inetnum)) {
                            index.addPrefix(p, answer);
                        }
                    }
                }
            }
        }

        return index.getMatch(prefix);
    }

    return answers;
};

const squashRemarksAndComments = (data) => {
    const out = [];
    for (let items of data) {
        const remarks = items.filter(i => i.key.toLowerCase() === "remarks");
        const comments = items.filter(i => i.key.toLowerCase() === "comment");
        const descr = items.filter(i => i.key.toLowerCase() === "descr");
        const rest = items.filter(i => !["remarks", "comment", "descr"].includes(i.key.toLowerCase()));
        out.push([
            ...rest,
            ...comments.length ? [{key: "Comment", value: comments.map(i => i.value)}] : [],
            ...remarks.length ? [{key: "remarks", value: remarks.map(i => i.value)}] : [],
            ...descr.length ? [{key: "descr", value: descr.map(i => i.value)}] : []
        ]);
    }

    return out;
};

const rangeToPrefix = (inetnum) => {
    return inetnum?.includes("-")
        ? ipUtils.ipRangeToCidr(...inetnum?.split("-").map(n => n.trim()))
        : [inetnum];
};

export const whois = ({query, fields = [], flag, timeout = 4000, servers = []}) => {
    fields = fields.map(i => i.toLowerCase()) ?? [];

    const _call = (command) => {
        let data = [];
        try {
            data = execSync(command, {encoding: "utf-8", timeout});
        } catch (error) {
            data = error.stdout;
        }

        return data.split("\n");
    };
    return new Promise((resolve, reject) => {
        try {
            flag = flag ?? (process.platform === "darwin" ? "s" : "h");
            const answers = [];

            if (servers.length > 0) {
                for (let server of servers) {
                    const command = `whois -${flag} ${server} "${query}"`;

                    answers.push({
                        server,
                        data: _call(command)
                    });
                }
            } else {
                const command = `whois "${query}"`;

                answers.push({
                    server: "",
                    data: _call(command)
                });
            }

            for (let answer of answers) {

                let out = [];
                let obj = [];
                for (let line of answer.data ?? []) {
                    if (line.length) {
                        const [key, ...value] = line.split(":").map(i => i.trim());
                        if (!key.startsWith("%") && !key.startsWith("#") && key !== "") {
                            if (fields.length === 0 || fields.includes(key.toLowerCase())) {
                                obj.push({key, value: value.join(":")});
                            }
                        }
                    } else {
                        out.push(obj);
                        obj = [];
                    }
                }
                answer.data = squashRemarksAndComments(out.filter(i => i.length));
            }

            resolve(answers.filter(i => i.data.length));
        } catch (error) {
            reject(error);
        }
    });
};

export const prefixLookupArin = ({query, ...params}) => {
    const parent = ipUtils.toPrefix(query);
    const [start] = ipUtils.cidrToRange(query);
    params = {flag: "h", timeout: 10000, ...params, servers: ["whois.arin.net"]};


    return Promise.all([
        whois({...params, query: parent}),
        whois({...params, query: start})
    ])
        .then(([a, b]) => {

            const arinParent = a?.find(i => i.server === "whois.arin.net");
            const arinChild = b?.find(i => i.server === "whois.arin.net");

            const index = new LongestPrefixMatch();
            let inetnums = [
                arinParent,
                arinChild
            ]
                .map(item => {
                    const inetnum = item?.data?.flat().find(n => n.key === "NetRange");

                    if (inetnum) {
                        return {
                            prefixes: rangeToPrefix(inetnum?.value),
                            data: item?.data
                        };
                    }
                })
                .filter(i => !!i);

            for (let {prefixes = [], data} of inetnums) {
                for (let p of prefixes) {
                    index.addPrefix(p, {
                        server: "whois.arin.net",
                        data
                    });
                }
            }

            return Promise.all(inetnums
                .map(i => i.prefixes).flat()
                .map(prefix => whois({...params, query: `r > ${prefix}`})))
                .then((data) => {

                    let suballocations = [...new Set(data.flat().map(i => i.data).flat().flat().map(i => i.key))]
                        .map(i => i.split(" "))
                        .filter(i => i.length >= 5)
                        .map(i => i.filter(n => n.match(/\(NET-([0-9]|-)*\)/) || ipUtils.isValidIP(n)))
                        .filter(i => i.length > 0)
                        .map(([id, start, stop]) => {

                            const prefixes = ipUtils.ipRangeToCidr(start, stop);
                            const handler = id.replace("(", "").replace(")", "");

                            return prefixes.map(prefix => (`${handler}|${prefix}`));

                        })
                        .flat();

                    suballocations = [...new Set(suballocations)]
                        .map(i => {
                            const [handler, prefix] = i.split("|");

                            return {handler, prefix};
                        });

                    for (let {prefix, handler} of suballocations) {
                        index.addPrefix(prefix, handler);
                    }

                    const handlers = index.getMatch(parent);

                    if (handlers.length > 0) {

                        if (handlers.filter(i => i.server).length) {
                            return [handlers.filter(i => i.server)[0]];
                        }


                        return Promise.all(handlers.filter(i => !i?.server).map(i => whois({...params, servers: Object.values(rirs), query: i})))
                            .then(i => {
                                const index = {};
                                for (let {server, data} of i.flat()) {
                                    index[server] ??= {server, data: []};
                                    index[server].data = index[server].data.concat(data);
                                }

                                return Object.values(index);
                            });
                    }

                    return [];
                });
        });
};

const _prefixLookup = ({query, flag}) => {
    const parent = ipUtils.toPrefix(query);
    const [start] = ipUtils.cidrToRange(parent);

    return Promise.all([
        whois({query: parent, flag, servers: []}),
        whois({query: start, flag, servers: []}),
        prefixLookupArin({query: parent, flag})
    ])
        .then(data => data.flat());
};

export const prefixLookup = ({query, fields, flag}) => {
    const parent = ipUtils.toPrefix(query);

    return _prefixLookup({query: parent, fields, flag})
        .then(data => filterFields(fields, data));
};

export const explicitTransferCheck = (params) => {
    return Promise.all(Object.values(rirs)
        .map(server => whois({...params, servers: [server]})));
};

export const lessSpecific = ({query, fields, flag}, callback, stop = 16) => {
    const parent = ipUtils.toPrefix(query);
    const [ip, bits] = ipUtils.getIpAndCidr(parent);
    const prefixes = [];
    for (let i = bits; i >= stop; i--) {
        prefixes.push(ipUtils.toPrefix([ip, i].join("/")));
    }

    let match = null;

    // This could be optimized by checking the last returned cidr and skipping queries that would produce the same answer
    return batchPromises(1, prefixes, prefix => {
        if (match) {
            return Promise.resolve();
        } else {
            return _prefixLookup({flag: "h", query: prefix})
                .then(data => {
                    if (callback(data)) {
                        match = data;
                    }
                });
        }
    })
        .then(() => filterMoreSpecific(match.flat(), parent));
};
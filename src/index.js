import ipUtils from 'ip-sub';
import LongestPrefixMatch from 'longest-prefix-match';

const execSync = require('child_process').execSync;

const rirs = {
    "ripe": "whois.ripe.net",
    "arin": "whois.arin.net",
    "lacnic": "whois.lacnic.net",
    "apnic": "whois.apnic.net",
    "afrinic": "whois.afrinic.net",
}

const getAuthority = (answers) => {
    const sen = "Allocated to ";
    const arin = answers?.find(i => i.server === "whois.arin.net");

    return arin?.data?.flat().find(n => n.key === "NetType" && n.value.includes(sen))?.value.replace(sen, "").replace(" NCC", "").toLowerCase() ?? null;
}

const setAuthority = (answers) => {
    const rir = getAuthority(answers);
    if (rir) {
        return answers.map(i => ({...i, authority: i.server.includes(rir)}));
    } else {
        return answers;
    }
}

const filterFields = (fields, data) => {
    if (fields.length > 0) {

        const out = [];
        for (let items of data) {
            out.push(items.filter(i => fields.includes(i.key.toLowerCase())));
        }

        return out.filter(i => i.length);
    } else {
        return data;
    }
}

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
            ...descr.length ? [{key: "descr", value: descr.map(i => i.value)}] : [],
        ]);
    }

    return out;
}

const _whois = ({query, fields=[], flag, timeout=4000, servers=Object.values(rirs)}) => {
    return new Promise((resolve, reject) => {
        try {
            flag = flag ?? (process.platform === "darwin" ? "s" : "h");
            const answers = [];
            for (let server of servers) {
                const command = `whois -${flag} ${server} "${query}"`;
                const data = execSync(command, {encoding: 'utf-8', timeout});

                answers.push({
                    server,
                    data: data.split("\n")
                });
            }

            for (let answer of answers) {

                let out = [];
                let obj = [];
                for (let line of answer.data ?? []) {
                    if (line.length) {
                        const [key, ...value] = line.split(":").map(i => i.trim());
                        if (!key.startsWith("%") && !key.startsWith("#") && key !== "") {
                            obj.push({key, value: value.join(":") });
                        }
                    } else {
                        out.push(obj);
                        obj = [];
                    }
                }
                answer.data = squashRemarksAndComments(filterFields(fields, out.filter(i => i.length)));
            }

            resolve(answers.filter(i => i.data.length));
        } catch (error) {
            reject(error);
        }
    });
}

export default function whois({servers, ...params}) {
    if (!servers) {
        return _whois({...params, timeout: 1000, servers: [rirs["arin"]]})
            .catch(() => [])
            .then(data => {
                const rir = getAuthority(data);

                if (rir) {
                    if (data[0]?.server.includes(rir)) {
                        return data;
                    } else {
                        const server = rirs[rir];
                        return _whois({...params, servers: [server]})
                    }
                } else {

                    return _whois(params)
                        .then(answers => {
                            return setAuthority(answers).filter(i => i.authority !== false);
                        });
                }
            })
    } else {
        return _whois({...params, servers})
            .then(setAuthority);
    }
}

export const prefixLookup = ({prefix, ...params}) => {
    const parent = ipUtils.toPrefix(prefix);
    const [start] = ipUtils.cidrToRange(parent);
    params = {flag: "h", timeout: 10000, ...params, servers: ["whois.arin.net"]};

    return Promise.all([
        _whois({...params, query: parent}),
        _whois({...params, query: start}),
    ])
        .then(([a, b]) => {
            const arinParent = a?.find(i => i.server === "whois.arin.net");
            const arinChild = b?.find(i => i.server === "whois.arin.net");

            const inetnums = [...new Set([
                arinParent?.data?.flat().find(n => n.key === "NetRange")?.value,
                arinChild?.data?.flat().find(n => n.key === "NetRange")?.value
            ])]
                .filter(i => !!i)
                .map(i => i?.includes("-")
                    ? ipUtils.ipRangeToCidr(...i.split("-").map(n => n.trim()))
                    : i
                )
                .flat();
            return Promise.all(inetnums.map(prefix => _whois({...params, query: `r > ${prefix}`})))
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

                    const index = new LongestPrefixMatch();

                    for (let {prefix, handler} of suballocations) {
                        index.addPrefix(prefix, handler);
                    }

                    const handlers = index.getMatch(parent);

                    if (handlers.length > 0) {

                        return Promise.all(index.getMatch(parent).map(i => _whois({...params, query: i})))
                            .then(i => {
                                const index = {};
                                for (let {server, data} of i.flat()) {
                                    index[server] ??= {server, data: []};
                                    index[server].data = index[server].data.concat(data);
                                }

                                return Object.values(index);
                            });
                    } else {
                        const rir = getAuthority(a);

                        if (rir) {
                            return _whois({...params, query: parent, servers: [rirs[rir]]});
                        } else {
                            return _whois({...params, query: parent, servers: Object.values(rirs)});
                        }

                    }
                })
                .then(data => {
                    if (data.length > 0) {
                        return data;
                    } else {
                        return arinParent;
                    }
                })
        })
}
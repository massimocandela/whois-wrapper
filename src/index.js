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

const _whois = ({query, flag, timeout=4000, servers=Object.values(rirs)}) => {
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
                answer.data = squashRemarksAndComments(out.filter(i => i.length));
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


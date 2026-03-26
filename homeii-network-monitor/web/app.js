async function load() {

const res = await fetch("/api/devices");
const data = await res.json();

document.getElementById("devices").innerHTML =
JSON.stringify(data);

}

load();

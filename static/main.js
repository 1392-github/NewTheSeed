function closeModal(id) {
    document.getElementById(id).style.display = "none"
    document.getElementById("modal_background").style.display = "none";
}
function openModal(id) {
    document.getElementById(id).style.display = "block"
    document.getElementById("modal_background").style.display = "block";
}
function onCaptchaCompleted(token) {
    document.getElementById("on-captcha").hidden = false;
}
function callapi(href, body, then) {
    fetch(href, {"method": "post",
    "headers": {"Content-Type": "application/json"},
    "body": JSON.stringify(body)})
    .then(r => {
        if (r.ok) return r.json()
        else if (r.status == 400) return r.text().then(t => {throw new Error(t)}) 
        else throw new Error(`Request failed with status code ${r.status}`)
    })
    .then(then)
    .catch(e => {alert(e.message)})
}
document.querySelectorAll(".confirm:not(.refresh-on-submit)").forEach(function (b) {
    b.addEventListener("submit", function (e) {
        if (!confirm("msg" in this.dataset ? this.dataset["msg"] : "계속하시겠습니까?")) {
            e.preventDefault();
        }
    })
})
document.querySelectorAll(".refresh-on-submit").forEach(function (form) {
    form.addEventListener("submit", function (e) {
        e.preventDefault();
        if (this.classList.contains("confirm")) {
            if (!confirm("msg" in this.dataset ? this.dataset["msg"] : "계속하시겠습니까?")) {
                return
            }
        }
        fetch(this.action, {method: this.method, body: new FormData(this)})
        .then((r) => {
            if (r.ok) {
                if ("customRedirect" in this.dataset) {
                    location.href = this.dataset.customRedirect
                }
                else {
                    location.reload()
                }
            }
            else {
                if (r.status >= 400 && r.status <= 499 && r.headers.get("Content-Type").startsWith("text/plain")) {
                    r.text().then(function (err) {
                        alert(err)
                    })
                }
                else {
                    alert(`Request failed with status code ${r.status}`)
                }
            }
        })
    })
})
document.body.addEventListener("click", function (e) {
    var t = e.target.closest(".toggle-button");
    if (t) {
        var target = document.getElementById(t.dataset.target);
        target.hidden = !target.hidden;
    }
})
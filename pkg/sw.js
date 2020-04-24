self.addEventListener('install', function(event) {
    console.log("Service worker installed");

    event.waitUntil(
        caches.open('v1').then(function(cache) {
            return cache.addAll([
                '/index.html',
                '/password_tool_bg.wasm',
                '/password_tool.js',
                '/parameters.png',
            ]);
        })
    );
});
  
self.addEventListener('fetch', function(event) {
    console.debug('The service worker is serving the ressource...');

    event.respondWith(caches.match(event.request).then(function(response) {
        // caches.match() always resolves
        // but in case of success response will have value
        if (response !== undefined) {
            return response;
        } else {
            return fetch(event.request).then(function (response) {
            // response may be used only once
            // we need to save clone to put one copy in cache
            // and serve second one
            let responseClone = response.clone();
            
            caches.open('v1').then(function (cache) {
                cache.put(event.request, responseClone);
            });
                return response;
            }).catch(function () {
                //return caches.match('/sw-test/gallery/myLittleVader.jpg');
            });
        }
    }));

    event.waitUntil(
        update(event.request)
            .then(console.debug("...and the ressource has been updated."))
    );
});

function update(request) {
    return caches.open("v1").then(function (cache) {
        return fetch(request).then(function (response) {
            return cache.put(request, response.clone()).then(function () {
                return response;
            });
        });
    });
}
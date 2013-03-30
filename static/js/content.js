function content_init() {
    // Load all dynamic content
    $(".content-head").each(function () {
        // Prepend the editing info
        var self = this;
        $(this).append($("#content-template").html());

        // Load the content
        $.get("/content/" + $(this).data("name"), function (data) {
            $(self).find(".content-view").html(Base64.decode(data.result));
        }, "json");
    });

    // Content editing
    $(".content-edit").hover(
        function (ev) {
            var pdiv = $(this).parent().parent();
            pdiv.css("background", "#eee");
        },

        function (ev) {
            var pdiv = $(this).parent().parent();
            pdiv.css("background", "none");
        }
    );

    $(".content-edit").click(function () {
        var pdiv = $(this).parent().parent();
        pdiv.find(".content-edit").hide();
        pdiv.find(".content-save").show();
        pdiv.find(".content-cancel").show();

        var contentDiv = pdiv.find(".content-view");
        var content = contentDiv.html();
        var w = contentDiv.width();
        var h = contentDiv.height();
        pdiv.data("old-content", content);
        contentDiv.html('');
        contentDiv.append($("<textarea>").css("width", w).css("height", h).text(content));
    });

    $(".content-cancel").click(function () {
        var pdiv = $(this).parent().parent();
        pdiv.find(".content-edit").show();
        pdiv.find(".content-save").hide();
        pdiv.find(".content-cancel").hide();

        var contentDiv = pdiv.find(".content-view");
        contentDiv.html(pdiv.data("old-content"));
    });

    $(".content-save").click(function () {
        // Save the content
        var pdiv = $(this).parent().parent();
        var contentDiv = pdiv.find(".content-view");
        var contentTextarea = pdiv.find(".content-view textarea");

        $.post("/content/" + pdiv.data("name"), {"content": Base64.encode(contentTextarea.val())}, function (data) {
            pdiv.find(".content-edit").show();
            pdiv.find(".content-save").hide();
            pdiv.find(".content-cancel").hide();

            contentDiv.html(Base64.decode(data.result));
        }, "json");
    });
}

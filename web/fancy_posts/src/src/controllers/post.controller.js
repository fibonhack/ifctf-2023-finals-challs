const { checkExact, checkSchema, validationResult } = require('express-validator');
const db = require('../models/db');
const { v4: uuidv4 } = require('uuid');

function renderPost(post) {
    if (!post?.content || typeof post.content !== 'string') return post;
    if (!post?.userid || typeof post.userid !== 'string') return post;
    if (!post?.id || typeof post.id !== 'string') return post;

    let properties = new Set(...post.content.matchAll(/\[\[[a-zA-Z0-9_]+\]\]/g));
    if (properties.size < 1) return post;
    const userProperties = db.prepare('SELECT p.key, p.value FROM property p WHERE p.user_id = :userid').all({ userid: post.userid });

    let newContent = post.content;
    properties.forEach(prop => {
        let propertyValue = userProperties.find(userProp => userProp.key === prop.substring(2, prop.length - 2))?.value ?? '';
        newContent = newContent.replaceAll(prop, propertyValue);
    });

    return {
        id: post.id,
        content: newContent,
    };
}

function post_list(req, res) {
    let posts = db
        .prepare("SELECT p.id, SUBSTR(p.content, 1, INSTR(p.content, '#') - 1) AS content, SUBSTR(p.content, INSTR(p.content, '#') + 1) AS userid FROM post p WHERE p.user_id = :userid")
        .all({ userid: res.locals.userid })
        .map(renderPost);

    return res.send({
        success: true,
        data: {
            posts: posts.map(p => ({ id: p.id, content: p.content })),
        },
    });
}

const post_create = [
    checkExact(
        checkSchema(
            {
                content: {
                    isString: true,
                    notEmpty: true,
                },
            },
            ['body'],
        ),
    ),

    function (req, res) {
        if (!validationResult(req).isEmpty()) return res.status(400).send({ success: false, error: 'Invalid content parameter' });

        const newId = uuidv4();
        db.prepare('INSERT INTO post (id, user_id, content) VALUES (:id, :userid, :content)').run({ id: newId, userid: res.locals.userid, content: req.body.content + `#${res.locals.userid}` });
        return res.status(201).send({
            success: true,
            data: {
                post: {
                    id: newId,
                    content: req.body.content,
                },
            },
        });
    },
];

const post_delete = [
    checkExact(
        checkSchema(
            {
                id: {
                    isString: true,
                    isUUID: true,
                },
            },
            ['params'],
        ),
    ),

    function (req, res) {
        if (!validationResult(req).isEmpty()) return res.status(400).send({ success: false, error: 'Invalid post id' });

        let oldPost = db
            .prepare("SELECT p.id, SUBSTR(p.content, 1, INSTR(p.content, '#') - 1) AS content FROM post p WHERE p.user_id = :userid AND p.id = :id")
            .get({ userid: res.locals.userid, id: req.params.id });
        if (oldPost === undefined)
            return res.status(404).send({
                success: false,
                error: 'No post found with the given id',
            });

        db.prepare('DELETE FROM post WHERE user_id = :userid AND id = :id').run({ id: req.params.id, userid: res.locals.userid });
        return res.status(200).send({
            success: true,
            data: {
                post: {
                    id: oldPost.id,
                    content: oldPost.content,
                },
            },
        });
    },
];

module.exports = {
    post_list,
    post_create,
    post_delete,
};

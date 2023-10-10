const { checkSchema, checkExact, validationResult } = require('express-validator');
const db = require('../models/db');
const { v4: uuidv4 } = require('uuid');

function profile_get(req, res) {
    return res.status(200).json({
        success: true,
        data: {
            id: res.locals.userid,
            username: res.locals.username,
        },
    });
}

function property_list(req, res) {
    const properties = db.prepare('SELECT p.id, p.key, p.value FROM property p WHERE p.user_id = :userid').all({ userid: res.locals.userid });

    return res.send({
        success: true,
        data: { properties: properties },
    });
}

const property_create = [
    checkExact(
        checkSchema(
            {
                key: {
                    errorMessage: 'Invalid key parameter',
                    isString: true,
                    isLength: {
                        options: { min: 2, max: 64 },
                    },
                    matches: {
                        options: /^[\w]+$/,
                    },
                },
                value: {
                    errorMessage: 'Invalid value parameter',
                    isString: true,
                    notEmpty: true,
                },
            },
            ['body'],
        ),
    ),

    function (req, res) {
        const validationErrors = validationResult(req);
        if (!validationErrors.isEmpty()) return res.status(400).send({ success: false, error: validationErrors.array()[0].msg });

        let property = db.prepare('SELECT p.id FROM property p WHERE p.user_id = :userid AND p.key = :key').get({ userid: res.locals.userid, key: req.body.key });
        if (property !== undefined) return res.status(400).send({ success: false, error: 'Property key already exists' });

        const newId = uuidv4();
        db.prepare('INSERT INTO property (id, user_id, key, value) VALUES (:id, :userid, :key, :value)').run({ id: newId, userid: res.locals.userid, key: req.body.key, value: req.body.value });
        return res.status(201).send({
            success: true,
            data: {
                property: {
                    id: newId,
                    key: req.body.key,
                    value: req.body.value,
                },
            },
        });
    },
];

const property_delete = [
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
        if (!validationResult(req).isEmpty()) return res.status(400).send({ success: false, error: 'Invalid property id' });

        let oldProperty = db.prepare('SELECT p.id, p.key, p.value FROM property p WHERE p.user_id = :userid AND p.id = :id').get({ userid: res.locals.userid, id: req.params.id });
        if (oldProperty === undefined)
            return res.status(404).send({
                success: false,
                error: 'No property found with the given id',
            });

        db.prepare('DELETE FROM property WHERE user_id = :userid AND id = :id').run({ id: req.params.id, userid: res.locals.userid });
        return res.status(200).send({
            success: true,
            data: {
                property: {
                    id: oldProperty.id,
                    key: oldProperty.key,
                    value: oldProperty.value,
                },
            },
        });
    },
];

module.exports = {
    profile_get,
    property_list,
    property_create,
    property_delete,
};

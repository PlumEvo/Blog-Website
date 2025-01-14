const express = require("express");
const router = express.Router();
const Post = require('../models/Post');

/** GET 
 * / 
 * GET - HOME */
router.get("", async (req,res)=>{

    try {
        const locals  = {
            title: "NodeJs Blog",
            description: "Simple Blog Created with NodeJs , Express and MongoDB."
        }

        let perPage = 10;
        let page = req.query.page || 1;

        const data = await Post.aggregate([ { $sort : {createdAt: -1}} ])
        .skip(perPage * page - perPage)
        .limit(perPage)
        .exec();

        const count = await Post.countDocuments();
        const nextPage = parseInt(page) + 1;
        const hasNextPage = nextPage <= Math.ceil(count/perPage);

        res.render("index",{
            locals , 
            data,
            current: page,
            nextPage: hasNextPage ? nextPage : null
        });   

    } catch (error) {
        console.log(error);
    }


});

function insertPostData (){
    /*Post.insertMany([
        {
            title: "Building a Blog",
            body: "This is the body text"
        }
    ])*/    
};

// insertPostData();

/*router.get("", async (req,res)=>{

    const locals  = {
        title: "NodeJs Blog",
        description: "Simple Blog Created with NodeJs , Express and MongoDB."
    }

    try {
        const data = await Post.find();
        res.render("index",{locals , data});   
    } catch (error) {
        console.log(error);
    }


});*/


/** GET / POST: id */

router.get("/post/:id", async (req,res)=>{

    try {
        let slug = req.params.id;
        const data = await Post.findById({_id: slug});

        const locals  = {
            title: data.title,
            description: "Simple Blog Created with NodeJs , Express and MongoDB."
        }

        res.render("post",{locals , data});   

    } catch (error) {
        console.log(error);
    }


});

/** POST / 
 * SEARCH: id */

router.post("/search", async (req,res)=>{

    try {
        const locals  = {
            title: "Search",
            description: "Simple Blog Created with NodeJs , Express and MongoDB."
        }

        let searchTerm = req.body.searchTerm;
        const searchNoSpecial = searchTerm.replace(/[^a-zA-Z0-9 ]/g, "");

        const data = await Post.find({
            $or:[
                {title:{$regex: new RegExp(searchNoSpecial,'i')}},
                {body:{$regex: new RegExp(searchNoSpecial,'i')}}
            ]
        })

        res.render("search",{
            data,
            locals
        });   

    } catch (error) {
        console.log(error);
    }
});


router.get("/about",(req,res)=>{
    res.render("about");
});

module.exports = router;